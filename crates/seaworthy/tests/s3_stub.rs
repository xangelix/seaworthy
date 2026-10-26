//! The loopback S3 stub: a signature-REVALIDATING in-memory S3 speaking
//! the real XML shapes, and the client end to end against it.
//!
//! Every request's signature is recomputed from the wire bytes (the stub
//! re-parses the raw target and headers itself) and mismatches answer
//! `403 SignatureDoesNotMatch`, so URL assembly, header transport, query
//! encoding, and body hashing are genuinely exercised end to end. The
//! canonicalization code is shared with the signer; its correctness is
//! anchored externally by the KAT suite (`sigv4_vectors.rs`), the stub's
//! job is the transport path. The stub also enforces what the publisher
//! leans on: `If-None-Match: *`, the `x-amz-checksum-sha256` check, stored
//! type / cache rule / user metadata, and `ListObjectsV2` paging.
//!
//! The security properties pinned here: https-only except loopback, the
//! construction-time grammar of endpoint, bucket, region and prefix,
//! deadlines on every call (a black-holing endpoint), bounded response
//! bodies, no redirect ever followed, endpoint-controlled error text
//! stripped of control characters.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code: a panic is a test failure"
)]

mod http_stub;

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use futures_util::StreamExt as _;
use http_stub::{RawRequest, RawResponse, StubServer, percent_decode};
use seaworthy::s3::sigv4::{Credentials, Payload, SignRequest, Signer};
use seaworthy::s3::{PutOptions, PutOutcome, S3Backend, S3Config, StorageError, StoragePath};
use seaworthy_crypto::digest::sha256_hex;
use zeroize::Zeroizing;

const ACCESS_KEY: &str = "ACMESTUBACCESS";
const SECRET_KEY: &str = "acmeStubSecretKey00000000000000000000000";
const BUCKET: &str = "test-bucket";
/// The session token the stub expects, when it expects one.
const SESSION_TOKEN: &str = "FwoGZXIvYXdzEXAMPLESTUBSESSIONTOKEN";

struct StoredObject {
    body: Vec<u8>,
    etag: String,
    /// The stored `Content-Type` (what S3 serves back on GET/HEAD).
    content_type: Option<String>,
    /// The stored `Cache-Control`.
    cache_control: Option<String>,
    /// The stored `x-amz-checksum-sha256`.
    checksum_sha256: Option<String>,
    /// The `x-amz-meta-*` headers, by full header name.
    metadata: BTreeMap<String, String>,
}

/// Base64 (standard, padded): the `x-amz-checksum-*` encoding, hand-rolled
/// so the stub is an independent side.
fn b64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn sha256_b64(bytes: &[u8]) -> String {
    b64(&seaworthy_crypto::digest::sha256(bytes))
}

#[derive(Default)]
struct StubState {
    objects: HashMap<String, StoredObject>,
    /// Require (and validate) this session token on every request.
    session_token: Option<String>,
    /// Every request's (method, raw path, Host header), in order.
    seen: Vec<(String, String, String)>,
}

/// The stub's own signer (the same secret; the session token, when one
/// is expected, is checked as a signed header).
fn signer() -> Signer {
    Signer::new(
        Credentials {
            access_key_id: ACCESS_KEY.to_owned(),
            secret_access_key: Zeroizing::new(SECRET_KEY.to_owned()),
            session_token: None,
        },
        "auto".to_owned(),
        "s3".to_owned(),
    )
}

/// Re-validate the wire request's header signature. `Ok(())` = authentic;
/// `Err(response)` = the 403/400 to send.
fn validate_signature(
    request: &RawRequest,
    session_token: Option<&str>,
) -> Result<(), RawResponse> {
    let signer = signer();
    let query = request.query();
    let authz = request.header("authorization").unwrap_or_default();
    let Some(signed_headers) = authz
        .split("SignedHeaders=")
        .nth(1)
        .and_then(|rest| rest.split(',').next())
    else {
        return Err(RawResponse::s3_error(
            400,
            "AuthorizationHeaderMalformed",
            "missing",
        ));
    };
    let presented_sig = authz
        .split("Signature=")
        .nth(1)
        .unwrap_or_default()
        .to_owned();

    // S3 verifies the declared content hash against the wire body.
    let declared_hash = request.header("x-amz-content-sha256").unwrap_or_default();
    if declared_hash != sha256_hex(&request.body) {
        return Err(RawResponse::s3_error(
            400,
            "BadDigest",
            "the Content-Hash does not match the wire body",
        ));
    }
    // AWS refuses any `x-amz-*` request header the signature did not cover.
    let signed: Vec<&str> = signed_headers.split(';').collect();
    if request
        .headers
        .iter()
        .any(|(name, _)| name.starts_with("x-amz-") && !signed.contains(&name.as_str()))
    {
        return Err(RawResponse::s3_error(
            403,
            "AccessDenied",
            "There were headers present in the request which were not signed",
        ));
    }
    if let Some(expected) = session_token
        && (request.header("x-amz-security-token") != Some(expected)
            || !signed.contains(&"x-amz-security-token"))
    {
        return Err(RawResponse::s3_error(
            403,
            "InvalidToken",
            "the security token is missing or unsigned",
        ));
    }

    let amz_date = request.header("x-amz-date").unwrap_or_default().to_owned();
    // Every signed header but `host` (the dedicated field), with the wire's
    // values: `x-amz-date`, `x-amz-content-sha256` and the session token
    // included, so the canonical request is rebuilt from the wire alone.
    let headers: Vec<(String, String)> = signed_headers
        .split(';')
        .filter(|name| *name != "host")
        .map(|name| {
            (
                name.to_owned(),
                request.header(name).unwrap_or_default().to_owned(),
            )
        })
        .collect();
    let canonical = signer.canonical_request(&SignRequest {
        method: &request.method,
        host: request.header("host").unwrap_or_default(),
        // The wire path is percent-encoded; the signer encodes the raw one
        // (S3 decodes the target, then re-encodes it canonically).
        path: &percent_decode(request.path()),
        query,
        headers,
        payload: Payload::Sha256Hex(declared_hash),
        normalize_path: false,
        content_sha256_header: false,
        amz_datetime: &amz_date,
    });
    let sts = signer.string_to_sign(&amz_date, &canonical.text);
    if presented_sig != signer.signature(&amz_date, &sts).expect("sign") {
        return Err(RawResponse::s3_error(
            403,
            "SignatureDoesNotMatch",
            "header signature mismatch",
        ));
    }
    Ok(())
}

/// The stub's request handler.
fn handle(state: &Arc<Mutex<StubState>>, request: RawRequest) -> RawResponse {
    let session_token = {
        let mut state = state.lock().expect("state");
        state.seen.push((
            request.method.clone(),
            request.path().to_owned(),
            request.header("host").unwrap_or_default().to_owned(),
        ));
        state.session_token.clone()
    };
    if let Err(response) = validate_signature(&request, session_token.as_deref()) {
        return response;
    }

    // Path-style addressing: /{bucket}/{key...}
    let path = percent_decode(request.path());
    let key = path.strip_prefix(&format!("/{BUCKET}/")).map(str::to_owned);
    let query = request.query();
    let q = |name: &str| {
        query
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    };

    // Bucket-level: ListObjectsV2.
    if q("list-type").as_deref() == Some("2") {
        return list_objects_v2(state, &query);
    }

    let Some(key) = key else {
        return RawResponse::s3_error(404, "NoSuchBucket", "unknown bucket");
    };
    match request.method.as_str() {
        "PUT" => {
            let checksum = request.header("x-amz-checksum-sha256").map(str::to_owned);
            if let Some(sent) = &checksum
                && *sent != sha256_b64(&request.body)
            {
                return RawResponse::s3_error(400, "BadDigest", "checksum mismatch");
            }
            let mut state = state.lock().expect("state");
            if request.header("if-none-match") == Some("*") && state.objects.contains_key(&key) {
                return RawResponse::s3_error(
                    412,
                    "PreconditionFailed",
                    "At least one of the pre-conditions you specified did not hold",
                );
            }
            let etag = format!("\"{}\"", &sha256_hex(&request.body)[..32]);
            let object = StoredObject {
                body: request.body.clone(),
                etag: etag.clone(),
                content_type: request.header("content-type").map(str::to_owned),
                cache_control: request.header("cache-control").map(str::to_owned),
                checksum_sha256: checksum.clone(),
                metadata: request
                    .headers
                    .iter()
                    .filter(|(name, _)| name.starts_with("x-amz-meta-"))
                    .cloned()
                    .collect(),
            };
            state.objects.insert(key, object);
            let mut response = RawResponse::new(200, Vec::new()).with_header("etag", &etag);
            if let Some(checksum) = &checksum {
                response = response.with_header("x-amz-checksum-sha256", checksum);
            }
            response
        }
        "HEAD" | "GET" => {
            let state = state.lock().expect("state");
            let Some(object) = state.objects.get(&key) else {
                return if request.method == "HEAD" {
                    RawResponse::new(404, Vec::new())
                } else {
                    RawResponse::s3_error(404, "NoSuchKey", "The specified key does not exist.")
                };
            };
            let mut response = if request.method == "HEAD" {
                RawResponse::new(200, Vec::new())
                    .with_header("content-length", &object.body.len().to_string())
            } else {
                RawResponse::new(200, object.body.clone())
            }
            .with_header("etag", &object.etag)
            .with_header("last-modified", "Wed, 14 Oct 2026 12:00:00 GMT");
            if let Some(content_type) = &object.content_type {
                response = response.with_header("content-type", content_type);
            }
            if let Some(cache_control) = &object.cache_control {
                response = response.with_header("cache-control", cache_control);
            }
            for (name, value) in &object.metadata {
                response = response.with_header(name, value);
            }
            if request.header("x-amz-checksum-mode") == Some("ENABLED")
                && let Some(checksum) = &object.checksum_sha256
            {
                response = response.with_header("x-amz-checksum-sha256", checksum);
            }
            response
        }
        "DELETE" => {
            let mut state = state.lock().expect("state");
            state.objects.remove(&key);
            RawResponse::new(204, Vec::new())
        }
        _ => RawResponse::s3_error(405, "MethodNotAllowed", "unsupported"),
    }
}

/// ListObjectsV2 over the in-memory store: `max-keys` pages, the
/// continuation token is the last key of the previous page.
fn list_objects_v2(state: &Arc<Mutex<StubState>>, query: &[(String, String)]) -> RawResponse {
    let get = |name: &str| {
        query
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    };
    let prefix = get("prefix").unwrap_or_default();
    let max_keys: usize = get("max-keys").and_then(|v| v.parse().ok()).unwrap_or(1000);
    let after = get("continuation-token");
    let state = state.lock().expect("state");
    let mut keys: Vec<(&String, &StoredObject)> = state
        .objects
        .iter()
        .filter(|(k, _)| k.starts_with(&prefix))
        .filter(|(k, _)| {
            after
                .as_ref()
                .is_none_or(|after| k.as_str() > after.as_str())
        })
        .collect();
    keys.sort_by(|a, b| a.0.cmp(b.0));
    let truncated = keys.len() > max_keys;
    keys.truncate(max_keys);
    let mut contents = String::new();
    for (key, object) in &keys {
        let escaped = key.replace('&', "&amp;").replace('<', "&lt;");
        contents.push_str(&format!(
            "<Contents><Key>{escaped}</Key><LastModified>2026-10-14T12:00:00.000Z</LastModified><ETag>{}</ETag><Size>{}</Size></Contents>",
            object.etag.replace('"', "&quot;"),
            object.body.len()
        ));
    }
    let next = if truncated {
        format!(
            "<NextContinuationToken>{}</NextContinuationToken>",
            keys.last()
                .map(|(k, _)| k.replace('&', "&amp;").replace('<', "&lt;"))
                .unwrap_or_default()
        )
    } else {
        String::new()
    };
    RawResponse::new(
        200,
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult><Name>{BUCKET}</Name><Prefix>{prefix}</Prefix><MaxKeys>{max_keys}</MaxKeys><IsTruncated>{truncated}</IsTruncated>{next}{contents}</ListBucketResult>"
        ),
    )
    .with_header("content-type", "application/xml")
}

async fn spawn_stub_with_state(state: Arc<Mutex<StubState>>) -> StubServer {
    http_stub::spawn(move |request| handle(&state, request)).await
}

async fn spawn_stub() -> (StubServer, Arc<Mutex<StubState>>) {
    let state = Arc::new(Mutex::new(StubState::default()));
    let server = spawn_stub_with_state(state.clone()).await;
    (server, state)
}

fn config(addr: &str) -> S3Config {
    S3Config::new(BUCKET, "auto", ACCESS_KEY, SECRET_KEY).with_endpoint(format!("http://{addr}"))
}

fn backend(addr: &str) -> S3Backend {
    S3Backend::new(config(addr)).expect("backend")
}

fn spath(s: &str) -> StoragePath {
    StoragePath::new(s).expect("valid test path")
}

/// A streamed read's deadline in these tests: generous, nothing here is
/// slow.
const STREAM_DEADLINE: std::time::Duration = std::time::Duration::from_secs(60);

async fn collect(backend: &S3Backend, path: &StoragePath) -> Result<Vec<u8>, StorageError> {
    let mut stream = backend.get_stream(path, STREAM_DEADLINE).await?;
    let mut out = Vec::new();
    while let Some(chunk) = stream.next().await {
        out.extend_from_slice(&chunk?);
    }
    Ok(out)
}

#[tokio::test]
async fn put_head_get_stream_list_delete_roundtrip() {
    let (server, _state) = spawn_stub().await;
    let backend = backend(&server.addr);
    let path = spath("apt/dists/stable/InRelease");
    let payload = Bytes::from_static(b"hello storage");

    let options = PutOptions::create_only()
        .with_content_type("text/plain")
        .with_cache_control("public, max-age=60")
        .with_metadata("sha256", sha256_hex(&payload));
    let outcome = backend
        .put_object(&path, payload.clone(), &options)
        .await
        .expect("put");
    assert!(
        matches!(outcome, PutOutcome::Created { etag: Some(_), .. }),
        "{outcome:?}"
    );

    let detail = backend
        .head_object_detail(&path)
        .await
        .expect("head")
        .expect("present");
    assert_eq!(detail.size, 13);
    assert_eq!(detail.content_type.as_deref(), Some("text/plain"));
    assert_eq!(detail.cache_control.as_deref(), Some("public, max-age=60"));
    assert_eq!(
        detail.sha256,
        Some(sha256_b64(&payload)),
        "the stored checksum"
    );
    assert_eq!(
        detail.metadata.get("sha256").map(String::as_str),
        Some(sha256_hex(&payload).as_str())
    );

    let fetched = backend
        .get_object(&path, 1024)
        .await
        .expect("get")
        .expect("present");
    assert_eq!(fetched.body, payload);
    assert!(
        fetched.checksum_sha256.is_some(),
        "verified against the stored checksum"
    );
    assert_eq!(
        collect(&backend, &path).await.expect("stream"),
        b"hello storage"
    );

    // A zero-byte object round-trips too.
    let empty = spath("apt/empty.bin");
    backend
        .put_object(&empty, Bytes::new(), &PutOptions::create_only())
        .await
        .expect("put empty");
    assert_eq!(
        backend
            .head_object_detail(&empty)
            .await
            .expect("head")
            .expect("present")
            .size,
        0
    );
    assert!(collect(&backend, &empty).await.expect("stream").is_empty());

    let page = backend
        .list_objects_v2(&spath("apt"), None, None)
        .await
        .expect("list");
    let mut paths: Vec<&str> = page.objects.iter().map(|o| o.path.as_str()).collect();
    paths.sort_unstable();
    assert_eq!(paths, ["apt/dists/stable/InRelease", "apt/empty.bin"]);
    assert!(page.continuation.is_none());
    assert_eq!(
        page.objects
            .iter()
            .find(|o| o.path == "apt/empty.bin")
            .and_then(|o| o.last_modified.as_deref()),
        Some("2026-10-14T12:00:00.000Z")
    );

    backend.delete_object(&path).await.expect("delete");
    backend
        .delete_object(&path)
        .await
        .expect("delete is idempotent");
    assert!(
        backend
            .head_object_detail(&path)
            .await
            .expect("head")
            .is_none()
    );
    assert!(
        backend
            .get_object(&path, 1024)
            .await
            .expect("get")
            .is_none()
    );
    let missing = collect(&backend, &path)
        .await
        .expect_err("a missing key streams nothing");
    assert!(
        matches!(&missing, StorageError::S3 { code, .. } if code == "NoSuchKey"),
        "{missing:?}"
    );
    server.stop().await;
}

/// A create-only put never overwrites: the second write of the key (the
/// same bytes or others) is `AlreadyExists`, and the object is unchanged.
#[tokio::test]
async fn create_only_puts_never_overwrite() {
    let (server, state) = spawn_stub().await;
    let backend = backend(&server.addr);
    let path = spath("pool/acme_1.0.0_amd64.deb");
    let options = PutOptions::create_only();
    let first = Bytes::from_static(b"first");
    assert!(matches!(
        backend.put_object(&path, first.clone(), &options).await,
        Ok(PutOutcome::Created { .. })
    ));
    for body in [first.clone(), Bytes::from_static(b"second")] {
        assert_eq!(
            backend
                .put_object(&path, body, &options)
                .await
                .expect("put"),
            PutOutcome::AlreadyExists
        );
    }
    assert_eq!(
        state.lock().expect("state").objects[path.as_str()].body,
        b"first"
    );
    // Without the condition, the write replaces the object.
    let mut overwrite = PutOptions::create_only();
    overwrite.create_only = false;
    assert!(matches!(
        backend
            .put_object(&path, Bytes::from_static(b"second"), &overwrite)
            .await,
        Ok(PutOutcome::Created { .. })
    ));
    server.stop().await;
}

/// The stub really validates signatures: a backend with the wrong secret
/// is refused, and a signed request replayed against another key (or with
/// an added, unsigned `x-amz-*` header) fails.
#[tokio::test]
async fn signature_tampering_is_rejected() {
    let (server, _state) = spawn_stub().await;
    let wrong = S3Backend::new(
        S3Config::new(
            BUCKET,
            "auto",
            ACCESS_KEY,
            "a-different-secret-key-0000000000000000",
        )
        .with_endpoint(server.url()),
    )
    .expect("backend");
    let error = wrong
        .head_object_detail(&spath("x.bin"))
        .await
        .expect_err("a wrong secret is refused");
    assert!(
        matches!(
            &error,
            StorageError::Http {
                status_code: 403,
                ..
            }
        ),
        "{error:?}"
    );
    assert!(!error.is_retryable());
    let error = wrong
        .get_object(&spath("x.bin"), 10)
        .await
        .expect_err("refused");
    assert!(
        matches!(&error, StorageError::S3 { code, .. } if code == "SignatureDoesNotMatch"),
        "{error:?}"
    );

    // A request signed for one key, sent to another.
    let signer = signer();
    let amz_date = seaworthy::s3::sigv4::current_amz_datetime();
    let empty = sha256_hex(b"");
    let signed = signer
        .signed_headers(&SignRequest {
            method: "GET",
            host: &server.addr,
            path: &format!("/{BUCKET}/a.bin"),
            query: Vec::new(),
            headers: Vec::new(),
            payload: Payload::Sha256Hex(&empty),
            normalize_path: false,
            content_sha256_header: true,
            amz_datetime: &amz_date,
        })
        .expect("sign");
    let client = backend(&server.addr);
    let send = |path: &'static str, extra: Option<(&'static str, &'static str)>| {
        let mut request = client
            .http_client()
            .get(format!("{}/{BUCKET}/{path}", server.url()));
        for (name, value) in &signed {
            request = request.header(name, value);
        }
        if let Some((name, value)) = extra {
            request = request.header(name, value);
        }
        request.send()
    };
    assert_eq!(
        send("b.bin", None).await.expect("sent").status().as_u16(),
        403
    );
    assert_eq!(
        send("a.bin", Some(("x-amz-acl", "public-read")))
            .await
            .expect("sent")
            .status()
            .as_u16(),
        403,
        "an unsigned x-amz-* header is refused"
    );
    // The untampered request authenticates (the key is missing: 404).
    assert_eq!(
        send("a.bin", None).await.expect("sent").status().as_u16(),
        404
    );
    server.stop().await;
}

/// An STS session token rides every request, signed.
#[tokio::test]
async fn the_session_token_rides_every_request() {
    let state = Arc::new(Mutex::new(StubState {
        session_token: Some(SESSION_TOKEN.to_owned()),
        ..StubState::default()
    }));
    let server = spawn_stub_with_state(state.clone()).await;
    let with_token =
        S3Backend::new(config(&server.addr).with_session_token(SESSION_TOKEN)).expect("backend");
    let path = spath("keys/acme.asc");
    with_token
        .put_object(
            &path,
            Bytes::from_static(b"key"),
            &PutOptions::create_only(),
        )
        .await
        .expect("put");
    assert!(
        with_token
            .head_object_detail(&path)
            .await
            .expect("head")
            .is_some()
    );
    with_token
        .list_objects_v2(&spath("keys"), None, None)
        .await
        .expect("list");
    with_token.delete_object(&path).await.expect("delete");
    // Without it, the stub refuses.
    let error = backend(&server.addr)
        .get_object(&path, 10)
        .await
        .expect_err("no token");
    assert!(
        matches!(&error, StorageError::S3 { code, .. } if code == "InvalidToken"),
        "{error:?}"
    );
    server.stop().await;
}

/// Listing pages through `max-keys` and the continuation token; a page
/// that says it is truncated but names no way to continue is an error,
/// never a short listing read as complete.
#[tokio::test]
async fn listing_pages_and_refuses_a_dead_end() {
    let (server, _state) = spawn_stub().await;
    let backend = backend(&server.addr);
    for key in [
        "plans/a.json",
        "plans/b&c.json",
        "plans/c.json",
        "other/d.json",
    ] {
        backend
            .put_object(
                &spath(key),
                Bytes::from_static(b"{}"),
                &PutOptions::create_only(),
            )
            .await
            .expect("put");
    }
    let mut listed = Vec::new();
    let mut continuation: Option<String> = None;
    let mut pages = 0;
    loop {
        let page = backend
            .list_objects_v2(&spath("plans"), Some(2), continuation.as_deref())
            .await
            .expect("page");
        pages += 1;
        listed.extend(page.objects.into_iter().map(|o| o.path));
        match page.continuation {
            Some(next) => continuation = Some(next),
            None => break,
        }
    }
    assert_eq!(pages, 2);
    assert_eq!(listed, ["plans/a.json", "plans/b&c.json", "plans/c.json"]);
    server.stop().await;

    let server = http_stub::spawn(|_| {
        RawResponse::new(
            200,
            "<ListBucketResult><IsTruncated>true</IsTruncated></ListBucketResult>",
        )
    })
    .await;
    assert!(matches!(
        backend_on(&server)
            .list_objects_v2(&spath("plans"), None, None)
            .await,
        Err(StorageError::Xml(_))
    ));
    server.stop().await;
}

fn backend_on(server: &StubServer) -> S3Backend {
    backend(&server.addr)
}

// ------------------------------------------------------------------------------------------------
// Management calls are deadline-bounded: a black-holing endpoint (accepts,
// never responds) must not park a caller forever.
// ------------------------------------------------------------------------------------------------

#[tokio::test]
async fn management_calls_are_bounded_by_the_configured_timeout() {
    let server = http_stub::spawn_hanging().await;
    let backend = S3Backend::new(
        config(&server.addr).with_management_timeout(std::time::Duration::from_millis(200)),
    )
    .expect("backend");
    let start = std::time::Instant::now();
    let path = spath("x.bin");
    for result in [
        backend.head_object_detail(&path).await.map(drop),
        backend.get_object(&path, 10).await.map(drop),
        backend.get_stream(&path, STREAM_DEADLINE).await.map(drop),
        backend.delete_object(&path).await,
        backend
            .put_object(&path, Bytes::from_static(b"x"), &PutOptions::create_only())
            .await
            .map(drop),
    ] {
        assert!(
            matches!(result, Err(StorageError::Timeout)),
            "typed Timeout, got: {result:?}"
        );
    }
    assert!(
        start.elapsed() < std::time::Duration::from_secs(10),
        "bounded at the configured knob, not the TCP stack's mercy"
    );
    server.stop().await;
}

/// A streamed read runs under its own total deadline: a store trickling
/// a byte at a time (each well inside the per-read timeout) can't keep
/// the reader past it. Deadlines out of range are refused before any
/// request.
#[tokio::test]
async fn a_streamed_read_is_bounded_by_its_total_deadline() {
    let server = http_stub::spawn_trickling(1000, std::time::Duration::from_millis(100)).await;
    let backend = backend_on(&server);
    let path = spath("apt/pool/a.deb");
    let start = std::time::Instant::now();
    let mut stream = backend
        .get_stream(&path, std::time::Duration::from_millis(500))
        .await
        .expect("the head arrives at once");
    let mut read = 0;
    let ended = loop {
        match stream.next().await {
            Some(Ok(chunk)) => read += chunk.len(),
            Some(Err(error)) => break error,
            None => panic!("the trickle ended the body after {read} bytes"),
        }
    };
    assert!(matches!(ended, StorageError::Timeout), "{ended:?}");
    assert!(read < 1000, "{read}");
    assert!(stream.next().await.is_none(), "nothing after the timeout");
    assert!(
        start.elapsed() < std::time::Duration::from_secs(10),
        "{:?}",
        start.elapsed()
    );
    for deadline in [
        std::time::Duration::ZERO,
        seaworthy::s3::MAX_PUT_TIMEOUT + std::time::Duration::from_secs(1),
    ] {
        assert!(
            matches!(
                backend.get_stream(&path, deadline).await.map(drop),
                Err(StorageError::Validation(_))
            ),
            "{deadline:?}"
        );
    }
    server.stop().await;
}

#[tokio::test]
async fn list_is_bounded_by_the_management_timeout() {
    let server = http_stub::spawn_hanging().await;
    let backend = S3Backend::new(
        config(&server.addr).with_management_timeout(std::time::Duration::from_millis(200)),
    )
    .expect("backend");
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        backend.list_objects_v2(&spath("p"), None, None),
    )
    .await
    .expect("list must be bounded by management_timeout, not the read timeout");
    assert!(matches!(result, Err(StorageError::Timeout)), "{result:?}");
    server.stop().await;
}

// ------------------------------------------------------------------------------------------------
// Management XML bodies are read BOUNDED: a >cap "ListObjectsV2" fails
// loudly instead of being buffered whole and parsed (a truncated parse
// could silently mis-list).
// ------------------------------------------------------------------------------------------------

#[tokio::test]
async fn management_xml_bodies_are_capped() {
    let server = http_stub::spawn(move |_request: RawRequest| {
        RawResponse::new(200, vec![b'x'; 9 * 1024 * 1024]) // 9 MiB > the 8 MiB XML cap
    })
    .await;
    let backend = backend(&server.addr);
    let error = backend
        .list_objects_v2(&spath("p"), None, None)
        .await
        .expect_err("an over-cap XML body must fail");
    assert!(
        format!("{error}").contains("cap"),
        "the cap is named, got: {error}"
    );
    server.stop().await;
}

// ------------------------------------------------------------------------------------------------
// Redirects are never followed: a SigV4 signature is host-bound, and a
// followed 307 would carry the signed headers (session token included) and
// the body to another host.
// ------------------------------------------------------------------------------------------------

#[tokio::test]
async fn redirects_are_never_followed() {
    let elsewhere = Arc::new(Mutex::new(0_usize));
    let hits = elsewhere.clone();
    let target = http_stub::spawn(move |_request: RawRequest| {
        *hits.lock().expect("hits") += 1;
        RawResponse::new(200, Vec::new())
    })
    .await;
    let location = format!("{}/{BUCKET}/stolen", target.url());
    let redirector = http_stub::spawn(move |_request: RawRequest| {
        RawResponse::new(307, Vec::new()).with_header("location", &location)
    })
    .await;
    let backend = S3Backend::new(config(&redirector.addr).with_session_token(SESSION_TOKEN))
        .expect("backend");
    let path = spath("x.bin");
    let put = backend
        .put_object(
            &path,
            Bytes::from_static(b"body"),
            &PutOptions::create_only(),
        )
        .await
        .expect_err("a 307 is a failure, not a hop");
    assert!(
        matches!(
            put,
            StorageError::Http {
                status_code: 307,
                ..
            }
        ),
        "{put:?}"
    );
    let get = backend.get_object(&path, 10).await.expect_err("307");
    assert!(
        matches!(
            get,
            StorageError::Http {
                status_code: 307,
                ..
            }
        ),
        "{get:?}"
    );
    assert_eq!(
        *elsewhere.lock().expect("hits"),
        0,
        "nothing reached the other host"
    );
    redirector.stop().await;
    target.stop().await;
}

// ------------------------------------------------------------------------------------------------
// Endpoint shape footguns fail at construction, not at the first request.
// ------------------------------------------------------------------------------------------------

#[test]
fn endpoint_with_path_or_userinfo_is_rejected() {
    let base = || S3Config::new(BUCKET, "auto", ACCESS_KEY, SECRET_KEY);
    // A path component can never sign correctly: the signer's raw_path
    // omits the endpoint prefix, so every request would 403.
    let error = S3Backend::new(base().with_endpoint("http://127.0.0.1:9000/storage/prefix"))
        .map(|_| ())
        .expect_err("an endpoint path component is rejected");
    assert!(
        matches!(error, StorageError::Validation(_)),
        "typed Validation, got: {error:?}"
    );
    // Credentials do not belong in a URL.
    let error = S3Backend::new(base().with_endpoint("http://user:pass@127.0.0.1:9000/"))
        .map(|_| ())
        .expect_err("endpoint userinfo is rejected");
    assert!(
        matches!(error, StorageError::Validation(_)),
        "typed Validation, got: {error:?}"
    );
    assert!(
        !format!("{error}").contains("pass"),
        "the userinfo is never echoed: {error}"
    );
}

/// Plaintext HTTP only to loopback: signed requests carry the session
/// token and credential-derived headers.
#[test]
fn endpoints_are_https_only_except_loopback() {
    let with = |endpoint: &str| {
        S3Backend::new(
            S3Config::new(BUCKET, "auto", ACCESS_KEY, SECRET_KEY).with_endpoint(endpoint),
        )
    };
    for good in [
        "https://storage.example.com",
        "https://storage.example.com:8443",
        "http://localhost:9000",
        "http://127.0.0.1:9000",
        "http://127.1.2.3",
        "http://[::1]:9000",
    ] {
        with(good).unwrap_or_else(|e| panic!("{good}: {e}"));
    }
    for bad in [
        "http://storage.example.com",
        "http://10.0.0.5:9000",
        "http://0.0.0.0:9000",
        "http://localhost.example.com:9000",
        "ftp://127.0.0.1",
        "file:///tmp/bucket",
        "not a url",
    ] {
        assert!(with(bad).is_err(), "{bad} must be refused");
    }
}

// ------------------------------------------------------------------------------------------------
// Endpoint-controlled error strings are control-character-stripped at the
// trust boundary: a hostile S3 must not forge log lines through
// StorageError.
// ------------------------------------------------------------------------------------------------

#[tokio::test]
async fn endpoint_controlled_error_strings_are_line_safe() {
    let server = http_stub::spawn(move |_request: RawRequest| {
        RawResponse::s3_error(403, "AccessDenied", "forged\r\nTRUSTED: all good")
    })
    .await;
    let error = backend(&server.addr)
        .get_object(&spath("x"), 10)
        .await
        .expect_err("403 fails");
    assert!(matches!(&error, StorageError::S3 { code, .. } if code == "AccessDenied"));
    // Display is the leak path: app logs render errors with `{}`, which
    // carries raw control chars.
    let rendered = format!("{error}");
    assert!(
        !rendered.contains('\r') && !rendered.contains('\n'),
        "S3 code/message are line-safe: {rendered:?}"
    );
    server.stop().await;

    // The raw-body (non-XML) path too.
    let server = http_stub::spawn(move |_request: RawRequest| {
        RawResponse::new(500, b"raw\r\nFORGED-LINE\x1b[2J".to_vec())
    })
    .await;
    let error = backend(&server.addr)
        .put_object(
            &spath("x"),
            Bytes::from_static(b"x"),
            &PutOptions::create_only(),
        )
        .await
        .expect_err("500 fails");
    assert!(error.is_retryable(), "a 5xx is transient");
    let rendered = format!("{error}");
    assert!(
        !rendered.contains('\r') && !rendered.contains('\n') && !rendered.contains('\x1b'),
        "raw error bodies are line-safe: {rendered:?}"
    );
    server.stop().await;
}

// ------------------------------------------------------------------------------------------------
// A LEADING `/` on the key prefix is normalized away: the prefix is a key
// fragment, not a path, and `/uploads` would address `/{bucket}//uploads/{key}`
// (a `//` no real layout has). The signature-revalidating stub records
// every raw path.
// ------------------------------------------------------------------------------------------------

#[tokio::test]
async fn key_prefix_leading_slash_is_normalized() {
    let (server, state) = spawn_stub().await;
    let backend =
        S3Backend::new(config(&server.addr).with_key_prefix("/uploads/")).expect("backend");
    let path = spath("2026/report.bin");
    backend
        .put_object(
            &path,
            Bytes::from_static(b"12345"),
            &PutOptions::create_only(),
        )
        .await
        .expect("put");
    let listed = backend
        .list_objects_v2(&spath("2026"), None, None)
        .await
        .expect("list");
    assert_eq!(listed.objects.len(), 1);
    assert_eq!(
        listed.objects[0].path, "2026/report.bin",
        "the prefix is stripped"
    );
    {
        let seen = &state.lock().expect("state").seen;
        assert!(
            seen.iter().all(|(_, path, _)| !path.contains("//")),
            "no `//` anywhere in the wire paths: {seen:?}"
        );
        assert!(
            seen.iter()
                .any(|(_, path, _)| path == "/test-bucket/uploads/2026/report.bin"),
            "the normalized prefix addresses `/<bucket>/uploads/…`: {seen:?}"
        );
    }
    server.stop().await;
}

// ------------------------------------------------------------------------------------------------
// Bucket-name validation at construction. Default (AWS) endpoints enforce
// the strict S3 grammar; custom endpoints (R2/RustFS accept wider names)
// get the floor rules.
// ------------------------------------------------------------------------------------------------

#[test]
fn bucket_names_are_validated_at_construction() {
    // Default endpoint = AWS: the strict S3 grammar.
    for bad in [
        "bad/name", "-nope", "x", "1.2.3.4", "Upper", "a..b", "-a", "a-",
    ] {
        let config = S3Config::new(bad, "us-east-1", ACCESS_KEY, SECRET_KEY);
        let error = S3Backend::new(config)
            .map(|_| ())
            .expect_err(&format!("{bad:?} refused"));
        assert!(
            matches!(error, StorageError::Validation(_)),
            "{bad:?}: typed Validation, got: {error:?}"
        );
        assert!(
            format!("{error}").contains(bad.trim_start_matches(['-', '.'])),
            "the refusal names the bucket: {error}"
        );
    }
    S3Backend::new(S3Config::new(
        "my-bucket",
        "us-east-1",
        ACCESS_KEY,
        SECRET_KEY,
    ))
    .expect("a grammar-clean bucket builds");

    // Custom endpoint: the floor rules only; wider names stay legal.
    S3Backend::new(
        S3Config::new("MixedCase", "auto", ACCESS_KEY, SECRET_KEY)
            .with_endpoint("http://127.0.0.1:1"),
    )
    .expect("custom endpoints accept wider names");
    for bad in ["", "bad/name", "has space", "ctl\u{7f}"] {
        let config =
            S3Config::new(bad, "auto", ACCESS_KEY, SECRET_KEY).with_endpoint("http://127.0.0.1:1");
        let error = S3Backend::new(config)
            .map(|_| ())
            .expect_err("floor refused");
        assert!(
            matches!(error, StorageError::Validation(_)),
            "{bad:?}: typed Validation, got: {error:?}"
        );
    }
}

#[test]
fn url_meaningful_bucket_region_and_prefix_are_refused() {
    let custom = |bucket: &str| {
        S3Config::new(bucket, "auto", ACCESS_KEY, SECRET_KEY).with_endpoint("http://127.0.0.1:1")
    };
    for bad in ["x@evil.example#", "a#b", "a?b", "a%2Fb", "a:b", "a\\b"] {
        let error = S3Backend::new(custom(bad))
            .map(|_| ())
            .expect_err(&format!("{bad:?} refused"));
        assert!(matches!(error, StorageError::Validation(_)), "{error:?}");
    }
    S3Backend::new(custom("Mixed_Case.bucket-1")).expect("[A-Za-z0-9._-] stays legal");

    for region in ["us east", "us-east-1/../x", "EU", ""] {
        let config = S3Config::new("my-bucket", region, ACCESS_KEY, SECRET_KEY);
        let error = S3Backend::new(config)
            .map(|_| ())
            .expect_err(&format!("region {region:?} refused"));
        assert!(matches!(error, StorageError::Validation(_)), "{error:?}");
    }
    for prefix in ["a/../b", "a//b", "a/./b"] {
        let config = custom("bucket").with_key_prefix(prefix);
        let error = S3Backend::new(config)
            .map(|_| ())
            .expect_err(&format!("prefix {prefix:?} refused"));
        assert!(matches!(error, StorageError::Validation(_)), "{error:?}");
    }
}

#[test]
fn virtual_host_style_refuses_ip_literal_endpoints() {
    let config = S3Config::new(BUCKET, "auto", ACCESS_KEY, SECRET_KEY)
        .with_endpoint("http://127.0.0.1:9000")
        .with_path_style(false);
    let error = S3Backend::new(config).map(|_| ()).expect_err("refused");
    assert!(matches!(error, StorageError::Validation(_)), "{error:?}");
}

/// Virtual-hosted style with a custom endpoint rides the CUSTOM endpoint,
/// never `*.amazonaws.com`.
#[test]
fn virtual_host_style_targets_the_custom_endpoint() {
    let backend = S3Backend::new(
        S3Config::new(BUCKET, "auto", ACCESS_KEY, SECRET_KEY)
            .with_endpoint("http://localhost:9000")
            .with_path_style(false),
    )
    .expect("backend");
    let rendered = format!("{backend:?}");
    assert!(
        rendered.contains("authority: \"test-bucket.localhost:9000\""),
        "{rendered}"
    );
    assert!(!rendered.contains("amazonaws.com"), "{rendered}");
}
