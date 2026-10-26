//! The S3 client against a REAL S3-compatible store: RustFS, self-provisioned
//! through `seaworthy-test-support` (no external credentials). Real SigV4,
//! real `If-None-Match: *` (a create-only put never overwrites), real
//! `x-amz-checksum-sha256` (verified on write, stored, echoed on read),
//! real user metadata, `Cache-Control`, `ListObjectsV2` paging and deletes:
//! everything the publisher relies on. Skips without a docker daemon; set
//! `SEAWORTHY_TEST_CONTAINERS_REQUIRED=1` to make the skip a hard failure.

#![cfg(unix)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code: a panic is a test failure"
)]

use bytes::Bytes;
use futures_util::StreamExt as _;
use seaworthy::s3::{PutOptions, PutOutcome, S3Backend, S3Config, StorageError, StoragePath};
use seaworthy_test_support::rustfs::Rustfs;

/// A backend on `bucket` of `rustfs`, under the key prefix `packages`.
fn backend_on(rustfs: &Rustfs, bucket: &str) -> S3Backend {
    S3Backend::new(
        S3Config::new(bucket, rustfs.region, rustfs.access_key, rustfs.secret_key)
            .with_endpoint(rustfs.endpoint_url.clone())
            .with_key_prefix("packages"),
    )
    .expect("backend")
}

fn spath(s: &str) -> StoragePath {
    StoragePath::new(s).expect("valid path")
}

fn b64_sha256(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(seaworthy_crypto::digest::sha256(bytes))
}

#[tokio::test]
async fn rustfs_create_only_puts_are_write_once_and_checksummed() {
    if !seaworthy_test_support::docker_or_skip().await {
        return;
    }
    let rustfs = seaworthy_test_support::rustfs::start_rustfs("acme-write-once").await;
    let backend = backend_on(&rustfs, &rustfs.bucket);
    let path = spath("plans/2026-10-14-0192a000.json");
    let first = Bytes::from_static(b"{\"plan\":1}");
    let options = PutOptions::create_only().with_content_type("application/json");

    let created = backend
        .put_object(&path, first.clone(), &options)
        .await
        .expect("the first write lands");
    assert!(
        matches!(created, PutOutcome::Created { .. }),
        "expected Created, got {created:?}"
    );

    // A retry of the same bytes and a DIFFERENT body are both refused:
    // nothing is overwritten; the caller compares.
    assert_eq!(
        backend
            .put_object(&path, first.clone(), &options)
            .await
            .expect("retry"),
        PutOutcome::AlreadyExists
    );
    assert_eq!(
        backend
            .put_object(&path, Bytes::from_static(b"{\"plan\":2}"), &options)
            .await
            .expect("conflicting write"),
        PutOutcome::AlreadyExists
    );

    let fetched = backend
        .get_object(&path, 1024)
        .await
        .expect("read back")
        .expect("present");
    assert_eq!(fetched.body, first);
    assert_eq!(
        fetched.checksum_sha256,
        Some(b64_sha256(&first)),
        "the stored SHA-256 is echoed and verified"
    );
    // Over the read bound: refused, never buffered.
    assert!(matches!(
        backend.get_object(&path, 4).await,
        Err(StorageError::Validation(_))
    ));
    assert!(
        backend
            .get_object(&spath("plans/missing.json"), 1024)
            .await
            .expect("a missing key reads as None")
            .is_none()
    );
}

#[tokio::test]
async fn rustfs_keeps_type_cache_rule_metadata_and_checksum() {
    if !seaworthy_test_support::docker_or_skip().await {
        return;
    }
    let rustfs = seaworthy_test_support::rustfs::start_rustfs("acme-detail").await;
    let backend = backend_on(&rustfs, &rustfs.bucket);
    let path = spath("apt/pool/main/a/acme/acme_1.0.0-1_amd64.deb");
    let body = Bytes::from(vec![7_u8; 100_000]);
    let sha256 = seaworthy_crypto::digest::sha256_hex(&body);
    backend
        .put_object(
            &path,
            body.clone(),
            &PutOptions::create_only()
                .with_content_type("application/vnd.debian.binary-package")
                .with_cache_control("public, max-age=31536000, immutable")
                .with_metadata("sha256", &sha256),
        )
        .await
        .expect("put");
    let detail = backend
        .head_object_detail(&path)
        .await
        .expect("head")
        .expect("present");
    assert_eq!(detail.size, 100_000);
    assert_eq!(
        detail.content_type.as_deref(),
        Some("application/vnd.debian.binary-package")
    );
    assert_eq!(
        detail.cache_control.as_deref(),
        Some("public, max-age=31536000, immutable")
    );
    assert_eq!(
        detail.metadata.get("sha256").map(String::as_str),
        Some(sha256.as_str())
    );
    if let Some(stored) = &detail.sha256 {
        assert_eq!(*stored, b64_sha256(&body), "the stored full-object SHA-256");
    }
    assert!(detail.etag.is_some() && detail.last_modified.is_some());
    assert_eq!(
        backend
            .head_object_detail(&spath("apt/missing"))
            .await
            .expect("head"),
        None
    );
}

#[tokio::test]
async fn rustfs_lists_pages_streams_and_deletes() {
    if !seaworthy_test_support::docker_or_skip().await {
        return;
    }
    let rustfs = seaworthy_test_support::rustfs::start_rustfs("acme-listing").await;
    let backend = backend_on(&rustfs, &rustfs.bucket);
    let keys = [
        "rpm/repodata/repomd.xml",
        "rpm/repodata/primary.xml.zst",
        "rpm/acme-1.0.0-1.x86_64.rpm",
        "rpm/acme-1.0.1-1.x86_64.rpm",
        "rpm/a+b c.txt",
    ];
    for key in keys {
        backend
            .put_object(
                &spath(key),
                Bytes::from(key.as_bytes().to_vec()),
                &PutOptions::create_only(),
            )
            .await
            .expect("put");
    }
    // A key outside the listed directory stays out of the listing.
    backend
        .put_object(
            &spath("rpmx/elsewhere"),
            Bytes::from_static(b"x"),
            &PutOptions::create_only(),
        )
        .await
        .expect("put");

    let mut listed = Vec::new();
    let mut continuation: Option<String> = None;
    let mut pages = 0;
    loop {
        let page = backend
            .list_objects_v2(&spath("rpm"), Some(2), continuation.as_deref())
            .await
            .expect("page");
        pages += 1;
        assert!(page.objects.len() <= 2, "max-keys honored");
        for object in &page.objects {
            assert!(object.last_modified.is_some(), "{object:?}");
        }
        listed.extend(page.objects.into_iter().map(|o| (o.path, o.size)));
        match page.continuation {
            Some(next) => continuation = Some(next),
            None => break,
        }
        assert!(pages < 10, "the listing terminates");
    }
    assert!(pages >= 3, "five keys at two per page: {pages}");
    listed.sort();
    let mut expected: Vec<(String, u64)> = keys
        .iter()
        .map(|k| ((*k).to_owned(), k.len() as u64))
        .collect();
    expected.sort();
    assert_eq!(listed, expected, "paths are relative to the key prefix");

    // A streamed read is byte-exact (a key needing percent-encoding too).
    for key in ["rpm/a+b c.txt", "rpm/repodata/repomd.xml"] {
        let mut stream = backend
            .get_stream(&spath(key), std::time::Duration::from_secs(60))
            .await
            .expect("stream");
        let mut body = Vec::new();
        while let Some(chunk) = stream.next().await {
            body.extend_from_slice(&chunk.expect("chunk"));
        }
        assert_eq!(body, key.as_bytes());
    }

    for key in keys {
        backend.delete_object(&spath(key)).await.expect("delete");
    }
    backend
        .delete_object(&spath(keys[0]))
        .await
        .expect("deleting a missing key is not an error");
    let page = backend
        .list_objects_v2(&spath("rpm"), None, None)
        .await
        .expect("list");
    assert!(page.objects.is_empty(), "{page:?}");
}

/// One container, several named buckets: each a real, separate bucket.
#[tokio::test]
async fn rustfs_serves_several_named_buckets_from_one_container() {
    if !seaworthy_test_support::docker_or_skip().await {
        return;
    }
    let rustfs =
        seaworthy_test_support::rustfs::start_rustfs_with_buckets(&["acme-stable", "acme-beta"])
            .await;
    assert_eq!(rustfs.buckets, ["acme-stable", "acme-beta"]);
    assert_eq!(rustfs.bucket, "acme-stable");
    let stable = backend_on(&rustfs, "acme-stable");
    let beta = backend_on(&rustfs, "acme-beta");
    let path = spath("publish-plan.json");
    stable
        .put_object(
            &path,
            Bytes::from_static(b"stable"),
            &PutOptions::create_only(),
        )
        .await
        .expect("put stable");
    beta.put_object(
        &path,
        Bytes::from_static(b"beta"),
        &PutOptions::create_only(),
    )
    .await
    .expect("put beta");
    assert_eq!(
        stable
            .get_object(&path, 64)
            .await
            .expect("get")
            .expect("present")
            .body,
        Bytes::from_static(b"stable")
    );
    assert_eq!(
        beta.get_object(&path, 64)
            .await
            .expect("get")
            .expect("present")
            .body,
        Bytes::from_static(b"beta")
    );
}
