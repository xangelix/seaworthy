//! The direct write-once operations' WIRE shapes, against a scripted
//! loopback stub: what `put_object` sends (the in-module SHA-256 checksum
//! on every write, `If-None-Match: *`, the type, cache rule and user
//! metadata, all SIGNED), how it reads the answers (`412` = already
//! exists for a create-only write, another version for an `If-Match` one,
//! an error otherwise; a lying checksum echo, a retryable `409`), and the
//! bounded,
//! verified `get_object` and `head_object_detail`. The real semantics
//! (conditional writes, stored checksums) are proven against RustFS in
//! `s3_rustfs.rs`.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code: a panic is a test failure"
)]

mod http_stub;

use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http_stub::{RawRequest, RawResponse};
use seaworthy::s3::{PutOptions, PutOutcome, S3Backend, S3Config, StorageError, StoragePath};

fn b64_sha256(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(seaworthy_crypto::digest::sha256(bytes))
}

fn backend(url: &str) -> S3Backend {
    S3Backend::new(
        S3Config::new(
            "evidence",
            "auto",
            "AKIDSTUB",
            "stub-secret-0000000000000000000000000000",
        )
        .with_endpoint(url.to_owned())
        .with_key_prefix("audit"),
    )
    .expect("backend")
}

fn spath(s: &str) -> StoragePath {
    StoragePath::new(s).expect("valid path")
}

/// The SignedHeaders list of a header-signed request.
fn signed_headers(request: &RawRequest) -> Vec<String> {
    request
        .header("authorization")
        .and_then(|authz| authz.split("SignedHeaders=").nth(1))
        .and_then(|rest| rest.split(',').next())
        .map(|list| list.split(';').map(str::to_owned).collect())
        .unwrap_or_default()
}

type Seen = Arc<Mutex<Vec<RawRequest>>>;

async fn stub(
    respond: impl Fn(&RawRequest) -> RawResponse + Send + Sync + 'static,
) -> (http_stub::StubServer, Seen) {
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    let server = http_stub::spawn(move |request: RawRequest| {
        let response = respond(&request);
        log.lock().expect("log").push(request);
        response
    })
    .await;
    (server, seen)
}

#[tokio::test]
async fn put_object_signs_the_checksum_and_the_condition() {
    let (server, seen) = stub(|request| {
        RawResponse::new(200, Vec::new())
            .with_header("etag", "\"e1\"")
            .with_header("x-amz-version-id", "v-1")
            .with_header(
                "x-amz-checksum-sha256",
                request.header("x-amz-checksum-sha256").unwrap_or_default(),
            )
    })
    .await;
    let backend = backend(&server.url());
    let body = Bytes::from_static(b"{\"run\":\"r1\"}");
    let outcome = backend
        .put_object(
            &spath("runs/r1.json"),
            body.clone(),
            &PutOptions::create_only().with_content_type("application/json"),
        )
        .await
        .expect("put");
    assert_eq!(
        outcome,
        PutOutcome::Created {
            etag: Some("\"e1\"".to_owned()),
            version_id: Some("v-1".to_owned()),
        }
    );
    let request = seen.lock().expect("log")[0].clone();
    assert_eq!(request.method, "PUT");
    assert_eq!(request.path(), "/evidence/audit/runs/r1.json");
    assert_eq!(request.body, body.to_vec());
    assert_eq!(
        request.header("x-amz-checksum-sha256"),
        Some(b64_sha256(&body).as_str()),
        "the body's SHA-256, computed in-module"
    );
    assert_eq!(
        request.header("x-amz-sdk-checksum-algorithm"),
        Some("SHA256")
    );
    assert_eq!(request.header("if-none-match"), Some("*"));
    let signed = signed_headers(&request);
    for header in [
        "content-type",
        "if-none-match",
        "x-amz-checksum-sha256",
        "x-amz-content-sha256",
        "x-amz-date",
    ] {
        assert!(
            signed.iter().any(|s| s == header),
            "{header} must be signed: {signed:?}"
        );
    }
    server.stop().await;
}

#[tokio::test]
async fn every_write_carries_the_checksum_and_an_unconditional_one_no_condition() {
    let (server, seen) = stub(|_| RawResponse::new(200, Vec::new())).await;
    let backend = backend(&server.url());
    let mut unconditional = PutOptions::create_only();
    unconditional.create_only = false;
    backend
        .put_object(&spath("a.bin"), Bytes::from_static(b"abc"), &unconditional)
        .await
        .expect("put");
    let request = seen.lock().expect("log")[0].clone();
    assert_eq!(
        request.header("x-amz-checksum-sha256"),
        Some(b64_sha256(b"abc").as_str())
    );
    assert!(request.header("if-none-match").is_none());
    server.stop().await;
}

#[tokio::test]
async fn a_precondition_failure_is_already_exists_never_an_overwrite() {
    let (server, _) = stub(|_| {
        RawResponse::s3_error(
            412,
            "PreconditionFailed",
            "At least one of the pre-conditions you specified did not hold",
        )
    })
    .await;
    let backend = backend(&server.url());
    assert_eq!(
        backend
            .put_object(
                &spath("a"),
                Bytes::from_static(b"x"),
                &PutOptions::create_only()
            )
            .await
            .expect("412 is an answer, not an error"),
        PutOutcome::AlreadyExists
    );
    server.stop().await;

    // A bare 412 (no XML body) reads the same.
    let (server, _) = stub(|_| RawResponse::new(412, Vec::new())).await;
    assert_eq!(
        backend_put(&server).await.expect("bare 412"),
        PutOutcome::AlreadyExists
    );
    server.stop().await;
}

/// A `412` is a condition's answer: an unconditional write that gets one
/// failed, never "already there"; an `If-Match` write that gets one (or a
/// `404`: nothing is there any more) found another version, and wrote
/// nothing.
#[tokio::test]
async fn a_412_means_what_the_condition_sent_says() {
    let (server, seen) = stub(|_| {
        RawResponse::s3_error(
            412,
            "PreconditionFailed",
            "At least one of the pre-conditions you specified did not hold",
        )
    })
    .await;
    let first = backend(&server.url());
    let mut unconditional = PutOptions::create_only();
    unconditional.create_only = false;
    let err = first
        .put_object(&spath("a"), Bytes::from_static(b"x"), &unconditional)
        .await
        .expect_err("an unconditional write's 412 is an error");
    assert!(err.to_string().contains("PreconditionFailed"), "{err}");
    let replacing = PutOptions::create_only().with_if_match("\"v1\"");
    assert_eq!(
        first
            .put_object(&spath("a"), Bytes::from_static(b"x"), &replacing)
            .await
            .expect("412 answers the condition"),
        PutOutcome::Changed
    );
    let request = seen
        .lock()
        .expect("log")
        .last()
        .cloned()
        .expect("a request");
    assert_eq!(request.header("if-match"), Some("\"v1\""));
    assert!(request.header("if-none-match").is_none());
    assert!(signed_headers(&request).contains(&"if-match".to_owned()));
    server.stop().await;
    let (server, _) = stub(|_| RawResponse::s3_error(404, "NoSuchKey", "gone")).await;
    assert_eq!(
        backend(&server.url())
            .put_object(&spath("a"), Bytes::from_static(b"x"), &replacing)
            .await
            .expect("a 404 answers the condition"),
        PutOutcome::Changed
    );
    server.stop().await;
    // Both conditions at once, or an ETag that can't be a header: refused
    // before any request.
    let mut both = PutOptions::create_only().with_if_match("\"v1\"");
    both.create_only = true;
    let (server, seen) = stub(|_| RawResponse::new(200, Vec::new())).await;
    let last = backend(&server.url());
    for options in [
        both,
        PutOptions::create_only().with_if_match("\"v1\"\r\nx: y"),
    ] {
        let err = last
            .put_object(&spath("a"), Bytes::from_static(b"x"), &options)
            .await
            .expect_err("refused");
        assert!(matches!(err, StorageError::Validation(_)), "{err}");
    }
    assert!(seen.lock().expect("log").is_empty());
    server.stop().await;
}

async fn backend_put(server: &http_stub::StubServer) -> Result<PutOutcome, StorageError> {
    backend(&server.url())
        .put_object(
            &spath("a"),
            Bytes::from_static(b"x"),
            &PutOptions::create_only(),
        )
        .await
}

#[tokio::test]
async fn a_lying_checksum_echo_fails_and_a_conditional_conflict_is_retryable() {
    let (server, _) = stub(|_| {
        RawResponse::new(200, Vec::new()).with_header("x-amz-checksum-sha256", &b64_sha256(b"y"))
    })
    .await;
    assert!(matches!(
        backend_put(&server).await,
        Err(StorageError::HashMismatch)
    ));
    server.stop().await;

    let (server, _) =
        stub(|_| RawResponse::s3_error(409, "ConditionalRequestConflict", "a concurrent write"))
            .await;
    let error = backend_put(&server).await.expect_err("409");
    assert!(error.is_retryable(), "{error:?}");
    server.stop().await;
}

#[tokio::test]
async fn bounds_are_checked_before_any_request() {
    let (server, seen) = stub(|_| RawResponse::new(200, Vec::new())).await;
    let backend = backend(&server.url());
    let oversized = Bytes::from(vec![
        0u8;
        usize::try_from(seaworthy::s3::MAX_DIRECT_OBJECT_BYTES)
            .expect("fits")
            + 1
    ]);
    assert!(matches!(
        backend
            .put_object(&spath("a"), oversized, &PutOptions::create_only())
            .await,
        Err(StorageError::Validation(_))
    ));
    let bad_type = PutOptions::create_only().with_content_type("text/plain\r\nx: y");
    assert!(matches!(
        backend
            .put_object(&spath("a"), Bytes::from_static(b"x"), &bad_type)
            .await,
        Err(StorageError::Validation(_))
    ));
    assert!(seen.lock().expect("log").is_empty(), "nothing was sent");
    server.stop().await;
}

#[tokio::test]
async fn get_object_verifies_the_stored_checksum_and_bounds_the_body() {
    let (server, seen) = stub(|request| {
        let body: &[u8] = b"witness line";
        let checksum = if request.path().ends_with("/lying") {
            b64_sha256(b"something else")
        } else {
            b64_sha256(body)
        };
        if request.path().ends_with("/missing") {
            return RawResponse::s3_error(404, "NoSuchKey", "not found");
        }
        RawResponse::new(200, body.to_vec())
            .with_header("x-amz-checksum-sha256", &checksum)
            .with_header("x-amz-version-id", "v-1")
    })
    .await;
    let backend = backend(&server.url());
    let fetched = backend
        .get_object(&spath("runs/r1.json"), 1024)
        .await
        .expect("read")
        .expect("present");
    assert_eq!(&fetched.body[..], b"witness line");
    assert_eq!(fetched.version_id.as_deref(), Some("v-1"));
    assert_eq!(fetched.checksum_sha256, Some(b64_sha256(b"witness line")));
    {
        let seen = seen.lock().expect("log");
        assert_eq!(seen[0].header("x-amz-checksum-mode"), Some("ENABLED"));
        assert!(
            signed_headers(&seen[0])
                .iter()
                .any(|h| h == "x-amz-checksum-mode")
        );
    }
    assert!(matches!(
        backend.get_object(&spath("runs/lying"), 1024).await,
        Err(StorageError::HashMismatch)
    ));
    assert!(matches!(
        backend.get_object(&spath("runs/r1.json"), 5).await,
        Err(StorageError::Validation(_))
    ));
    assert!(
        backend
            .get_object(&spath("missing"), 1024)
            .await
            .expect("404 is None")
            .is_none()
    );
    server.stop().await;
}

#[tokio::test]
async fn cache_control_is_signed_and_the_body_cap_can_be_raised_to_a_single_puts_limit() {
    let (server, seen) = stub(|request| {
        RawResponse::new(200, Vec::new()).with_header(
            "x-amz-checksum-sha256",
            request.header("x-amz-checksum-sha256").unwrap_or_default(),
        )
    })
    .await;
    let backend = backend(&server.url());
    let options = PutOptions::create_only()
        .with_content_type("application/vnd.debian.binary-package")
        .with_cache_control("public, max-age=31536000, immutable");
    backend
        .put_object(&spath("pool/a.deb"), Bytes::from_static(b"deb"), &options)
        .await
        .expect("put");
    let request = seen.lock().expect("log")[0].clone();
    assert_eq!(
        request.header("cache-control"),
        Some("public, max-age=31536000, immutable")
    );
    assert!(
        signed_headers(&request)
            .iter()
            .any(|s| s == "cache-control")
    );
    // Over the default cap: refused, unless the caller raises it.
    let big = Bytes::from(vec![
        7u8;
        usize::try_from(seaworthy::s3::MAX_DIRECT_OBJECT_BYTES)
            .expect("fits")
            + 1
    ]);
    assert!(matches!(
        backend
            .put_object(&spath("big"), big.clone(), &options)
            .await,
        Err(StorageError::Validation(_))
    ));
    backend
        .put_object(
            &spath("big"),
            big.clone(),
            &options.clone().with_max_body_bytes(big.len() as u64),
        )
        .await
        .expect("a raised cap");
    assert_eq!(
        seen.lock().expect("log").len(),
        2,
        "one refused before any request"
    );
    // Never past S3's single-PUT limit, and no header injection.
    for bad in [
        options
            .clone()
            .with_max_body_bytes(seaworthy::s3::MAX_SINGLE_PUT_BYTES + 1),
        options.clone().with_cache_control("no-store\r\nx-evil: 1"),
        options.clone().with_cache_control(""),
    ] {
        assert!(matches!(
            backend
                .put_object(&spath("a"), Bytes::from_static(b"x"), &bad)
                .await,
            Err(StorageError::Validation(_))
        ));
    }
    assert_eq!(seen.lock().expect("log").len(), 2);
    server.stop().await;
}

#[tokio::test]
async fn head_object_detail_reads_type_cache_and_the_full_object_checksum() {
    let (server, seen) = stub(|request| match request.path() {
        "/evidence/audit/missing" => RawResponse::new(404, Vec::new()),
        "/evidence/audit/multipart" => RawResponse::new(200, Vec::new())
            .with_header("content-length", "12")
            .with_header("x-amz-checksum-sha256", "abcd-3"),
        _ => RawResponse::new(200, Vec::new())
            .with_header("content-length", "3")
            .with_header("etag", "\"e\"")
            .with_header("last-modified", "Wed, 14 Oct 2026 12:00:00 GMT")
            .with_header("content-type", "application/x-rpm")
            .with_header("cache-control", "public, max-age=60")
            .with_header("x-amz-checksum-sha256", "c2hhMjU2")
            .with_header("x-amz-meta-sha256", "00ff"),
    })
    .await;
    let backend = backend(&server.url());
    let detail = backend
        .head_object_detail(&spath("present"))
        .await
        .expect("head")
        .expect("found");
    assert_eq!(
        detail,
        seaworthy::s3::ObjectDetail {
            size: 3,
            etag: Some("\"e\"".to_owned()),
            last_modified: Some("Wed, 14 Oct 2026 12:00:00 GMT".to_owned()),
            content_type: Some("application/x-rpm".to_owned()),
            cache_control: Some("public, max-age=60".to_owned()),
            sha256: Some("c2hhMjU2".to_owned()),
            metadata: [("sha256".to_owned(), "00ff".to_owned())].into(),
        }
    );
    let request = seen.lock().expect("log")[0].clone();
    assert_eq!(request.method, "HEAD");
    assert_eq!(request.header("x-amz-checksum-mode"), Some("ENABLED"));
    // A multipart object's composite checksum isn't the object's SHA-256.
    let multipart = backend
        .head_object_detail(&spath("multipart"))
        .await
        .expect("head")
        .expect("found");
    assert_eq!((multipart.size, multipart.sha256), (12, None));
    assert_eq!(
        backend
            .head_object_detail(&spath("missing"))
            .await
            .expect("head"),
        None
    );
    server.stop().await;
}

#[tokio::test]
async fn user_metadata_is_signed_and_checked() {
    let (server, seen) = stub(|_| RawResponse::new(200, Vec::new())).await;
    let backend = backend(&server.url());
    let options = PutOptions::create_only().with_metadata("sha256", "ab".repeat(32));
    backend
        .put_object(&spath("k"), Bytes::from_static(b"x"), &options)
        .await
        .expect("put");
    let request = seen.lock().expect("log")[0].clone();
    assert_eq!(
        request.header("x-amz-meta-sha256"),
        Some("ab".repeat(32).as_str())
    );
    assert!(
        signed_headers(&request)
            .iter()
            .any(|s| s == "x-amz-meta-sha256")
    );
    let mut too_many = PutOptions::create_only();
    for i in 0..=seaworthy::s3::MAX_USER_METADATA {
        too_many = too_many.with_metadata(format!("m{i}"), "v");
    }
    for bad in [
        PutOptions::create_only().with_metadata("Upper", "v"),
        PutOptions::create_only().with_metadata("a_b", "v"),
        PutOptions::create_only().with_metadata("", "v"),
        PutOptions::create_only().with_metadata("x".repeat(65), "v"),
        PutOptions::create_only()
            .with_metadata("a", "v")
            .with_metadata("a", "w"),
        PutOptions::create_only().with_metadata("a", "line\r\nx: y"),
        too_many,
        PutOptions::create_only()
            .with_timeout(seaworthy::s3::MAX_PUT_TIMEOUT + std::time::Duration::from_secs(1)),
        PutOptions::create_only().with_timeout(std::time::Duration::ZERO),
    ] {
        assert!(matches!(
            backend
                .put_object(&spath("k"), Bytes::from_static(b"x"), &bad)
                .await,
            Err(StorageError::Validation(_))
        ));
    }
    assert_eq!(
        seen.lock().expect("log").len(),
        1,
        "every refusal before any request"
    );
    server.stop().await;
}

/// A server that reads a request at `bytes_per_second`, then answers 200.
async fn slow_reader(bytes_per_second: usize) -> String {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut data = Vec::new();
                let chunk = (bytes_per_second / 10).max(1);
                let mut buf = vec![0_u8; chunk];
                let total = loop {
                    if let Some(end) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&data[..end]).to_lowercase();
                        let length: usize = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse().ok())
                            .unwrap_or(0);
                        break end + 4 + length;
                    }
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => data.extend_from_slice(&buf[..n]),
                    }
                };
                while data.len() < total {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => data.extend_from_slice(&buf[..n]),
                    }
                }
                let _ = stream
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .await;
            });
        }
    });
    format!("http://127.0.0.1:{port}")
}

#[tokio::test]
async fn a_large_put_runs_under_its_own_deadline() {
    // The management deadline (1 s here) is too short for a body the server
    // takes ~3 s to read; the put's own deadline isn't.
    let url = slow_reader(1024 * 1024).await;
    let backend = S3Backend::new(
        S3Config::new(
            "evidence",
            "us-east-1",
            "AKIDEXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        )
        .with_endpoint(url)
        .with_management_timeout(std::time::Duration::from_secs(1)),
    )
    .expect("backend");
    let body = Bytes::from(vec![1_u8; 3 * 1024 * 1024 + 512 * 1024]);
    let options = PutOptions::create_only().with_max_body_bytes(body.len() as u64);
    assert!(matches!(
        backend
            .put_object(&spath("big"), body.clone(), &options)
            .await,
        Err(StorageError::Timeout)
    ));
    backend
        .put_object(
            &spath("big"),
            body,
            &options.with_timeout(std::time::Duration::from_secs(30)),
        )
        .await
        .expect("within its own deadline");
}
