//! `seaworthy publish`.
//!
//! Against a real S3-compatible store (RustFS, `seaworthy_test_support`;
//! docker required, as in CI's container job): hand-made repositories
//! (files and their plan, no package tools) published and the bucket read
//! back object by object — the bytes, the SHA-256 metadata, `Content-Type`
//! and `Cache-Control` of every file, the upload order, the plan and its
//! history; idempotent re-publishing; what must be refused before
//! anything is uploaded; pruning by the plans' history; the fetch-back
//! through a public URL (a local proxy in front of the bucket that can
//! lie); the command. And once a real signed repository, as `repo` builds
//! it (package tools too).
//!
//! Against an in-memory S3 stand-in (no docker: these run everywhere):
//! the cases a real store won't stage on demand — an immutable file raced
//! into place, a publication stopped midway and resumed (never rolled
//! back), another publication moving the current plan meanwhile, a store
//! that doesn't keep what was sent, objects without the publisher's
//! metadata, a pruning failure.
//!
//! Skipped loudly without docker or the tools, unless
//! `SEAWORTHY_TEST_CONTAINERS_REQUIRED=1` / `SEAWORTHY_REQUIRE_PACKAGE_TOOLS=1`
//! turn the skip into a failure.

#![cfg(unix)]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use seaworthy::publish::{
    CURRENT_PLAN, Credentials, IMMUTABLE_CACHE, Options, Report, Target, content_type, publish,
};
use seaworthy::repo::{Class, Plan, PlanEntry};
use seaworthy::s3::{PutOptions, S3Backend, S3Config, StoragePath};

/// A plan date every test starts from: 2026-10-14 12:00:00 UTC.
const DATE: u64 = 1_791_979_200;
const DAY: u64 = 86_400;

// ---------------------------------------------------------------------------
// Hand-made repositories

/// A release's files: `(path, bytes, class)`.
type Files = Vec<(String, Vec<u8>, Class)>;

/// Release `version` of a one-product repository, as `repo` lays it out
/// (the bytes stand in for real packages).
fn release(version: &str) -> Files {
    let token = format!("{version}+b1");
    let tree = format!("releases/acme-agent/stable/{token}/x86_64-unknown-linux-gnu");
    vec![
        (
            format!("apt/pool/main/acme-agent/acme-agent_{version}-1_amd64.deb"),
            format!("deb {version}").into_bytes(),
            Class::Immutable,
        ),
        (
            format!("{tree}/acme-agent.deb"),
            format!("deb {version}").into_bytes(),
            Class::Immutable,
        ),
        (
            format!("{tree}/acme-agent.deb.manifest"),
            format!("manifest {version}").into_bytes(),
            Class::Immutable,
        ),
        (
            "keys/acme.asc".into(),
            b"-----BEGIN PGP PUBLIC KEY BLOCK-----\n".to_vec(),
            Class::Index,
        ),
        (
            "apt/dists/stable/InRelease".into(),
            format!("InRelease {version}").into_bytes(),
            Class::Index,
        ),
        (
            "rpm/stable/x86_64/repodata/repomd.xml".into(),
            format!("<repomd {version}/>").into_bytes(),
            Class::Index,
        ),
    ]
}

/// Writes `files` and their plan (dated `date`) into `dir`.
fn synthetic(dir: &Path, date: u64, files: &Files) -> Plan {
    let plan = Plan {
        repository: "acme".into(),
        channel: "stable".into(),
        url: None,
        rollback: false,
        date,
        releases: Vec::new(),
        tools: BTreeMap::new(),
        files: files
            .iter()
            .map(|(path, bytes, class)| PlanEntry {
                path: path.clone(),
                sha256: seaworthy_crypto::digest::sha256_hex(bytes),
                size: bytes.len() as u64,
                class: *class,
            })
            .collect(),
    };
    for (path, bytes, _) in files {
        let file = dir.join(path);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, bytes).unwrap();
    }
    std::fs::write(
        dir.join(seaworthy::repo::PLAN_FILE),
        format!("{}\n", serde_json::to_string_pretty(&plan).unwrap()),
    )
    .unwrap();
    plan
}

/// A fresh repository directory of `files` dated `date`.
fn repo_of(name: &str, date: u64, files: &Files) -> (tempfile::TempDir, PathBuf, Plan) {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join(name);
    let plan = synthetic(&repo, date, files);
    (dir, repo, plan)
}

fn options(now: u64) -> Options {
    Options {
        dry_run: false,
        prune: true,
        now,
    }
}

/// The upload order every publication follows: the immutable files, the
/// plan's history entry, the indexes, the plan.
fn assert_order(report: &Report, plan: &Plan) {
    let immutables: Vec<&str> = plan
        .files
        .iter()
        .filter(|f| f.class == Class::Immutable && !report.skipped.contains(&f.path))
        .map(|f| f.path.as_str())
        .collect();
    let indexes: Vec<&str> = plan
        .files
        .iter()
        .filter(|f| f.class == Class::Index)
        .map(|f| f.path.as_str())
        .collect();
    let uploaded: Vec<&str> = report.uploaded.iter().map(String::as_str).collect();
    let n = immutables.len();
    assert_eq!(&uploaded[..n], immutables.as_slice(), "{uploaded:?}");
    assert!(
        uploaded[n].starts_with(&format!("plans/{}-", plan.date)),
        "the history before any index: {uploaded:?}"
    );
    assert_eq!(&uploaded[n + 1..n + 1 + indexes.len()], indexes.as_slice());
    assert_eq!(uploaded[n + 1 + indexes.len()..], [CURRENT_PLAN]);
}

// ---------------------------------------------------------------------------
// RustFS

/// A RustFS bucket, the runtime driving it, and a backend that sees the
/// whole bucket (no prefix).
struct Bucket {
    runtime: tokio::runtime::Runtime,
    rustfs: Option<seaworthy_test_support::rustfs::Rustfs>,
    inspect: Arc<S3Backend>,
}

impl Bucket {
    fn start(name: &str) -> Option<Self> {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        if !runtime.block_on(seaworthy_test_support::docker_or_skip()) {
            return None;
        }
        let rustfs = runtime.block_on(seaworthy_test_support::rustfs::start_rustfs(name));
        let inspect = Arc::new(
            S3Backend::new(
                S3Config::new(
                    rustfs.bucket.clone(),
                    rustfs.region,
                    rustfs.access_key,
                    rustfs.secret_key,
                )
                .with_endpoint(rustfs.endpoint_url.clone()),
            )
            .unwrap(),
        );
        Some(Self {
            runtime,
            rustfs: Some(rustfs),
            inspect,
        })
    }

    fn rustfs(&self) -> &seaworthy_test_support::rustfs::Rustfs {
        self.rustfs.as_ref().unwrap()
    }

    fn target(&self) -> Target {
        let rustfs = self.rustfs();
        Target {
            endpoint: rustfs.endpoint_url.clone(),
            bucket: rustfs.bucket.clone(),
            region: rustfs.region.to_owned(),
            prefix: "packages".into(),
            public_url: None,
            index_max_age_seconds: 60,
            retention_days: 30,
        }
    }

    fn credentials(&self) -> Credentials {
        let rustfs = self.rustfs();
        Credentials::new(rustfs.access_key.into(), rustfs.secret_key.into(), None)
    }

    /// Every key in the bucket.
    fn keys(&self) -> BTreeSet<String> {
        self.runtime.block_on(async {
            let mut keys = BTreeSet::new();
            for top in ["packages", "elsewhere"] {
                let prefix = StoragePath::new(top).unwrap();
                let mut continuation: Option<String> = None;
                loop {
                    let page = self
                        .inspect
                        .list_objects_v2(&prefix, None, continuation.as_deref())
                        .await
                        .unwrap();
                    keys.extend(page.objects.into_iter().map(|o| o.path));
                    match page.continuation {
                        Some(next) => continuation = Some(next),
                        None => break,
                    }
                }
            }
            keys
        })
    }

    fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.runtime.block_on(async {
            self.inspect
                .get_object(&StoragePath::new(key).unwrap(), 1 << 30)
                .await
                .unwrap()
                .map(|o| o.body.to_vec())
        })
    }

    fn detail(&self, key: &str) -> seaworthy::s3::ObjectDetail {
        self.runtime.block_on(async {
            self.inspect
                .head_object_detail(&StoragePath::new(key).unwrap())
                .await
                .unwrap()
                .unwrap_or_else(|| panic!("{key} is missing"))
        })
    }

    fn put(&self, key: &str, body: &[u8]) {
        self.runtime.block_on(async {
            self.inspect
                .put_object(
                    &StoragePath::new(key).unwrap(),
                    Bytes::from(body.to_vec()),
                    &PutOptions::create_only(),
                )
                .await
                .unwrap();
        });
    }
}

impl Drop for Bucket {
    fn drop(&mut self) {
        // The container goes with the runtime that started it.
        let rustfs = self.rustfs.take();
        self.runtime.block_on(async move { drop(rustfs) });
    }
}

fn files_of(dir: &Path, base: &Path, out: &mut BTreeSet<String>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files_of(&path, base, out);
        } else {
            out.insert(
                path.strip_prefix(base)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned(),
            );
        }
    }
}

#[test]
fn a_repository_is_published_in_order_with_its_cache_rules() {
    let Some(bucket) = Bucket::start("publish-order") else {
        return;
    };
    let (_dir, repo, plan) = repo_of("r1", DATE, &release("1.0.0"));
    let (target, credentials) = (bucket.target(), bucket.credentials());
    // A dry run checks everything and writes nothing.
    let dry = publish(
        &repo,
        &target,
        &credentials,
        &Options {
            dry_run: true,
            prune: true,
            now: DATE,
        },
    )
    .unwrap();
    assert!(bucket.keys().is_empty(), "a dry run wrote");
    assert!(dry.deleted.is_empty());

    let report = publish(&repo, &target, &credentials, &options(DATE + 60)).unwrap();
    assert_eq!(
        report.uploaded, dry.uploaded,
        "the dry run's report is the run's"
    );
    assert!(!report.already_published && report.skipped.is_empty());
    assert_order(&report, &plan);
    let history = format!("packages/{}", report.uploaded[3]);
    // Every file: its bytes, their SHA-256 in metadata, its type and its
    // cache rule.
    for file in &plan.files {
        let key = format!("packages/{}", file.path);
        let detail = bucket.detail(&key);
        assert_eq!(detail.size, file.size, "{key}");
        assert_eq!(detail.metadata.get("sha256"), Some(&file.sha256), "{key}");
        assert_eq!(
            detail.content_type.as_deref(),
            Some(content_type(&file.path)),
            "{key}"
        );
        let cache = match file.class {
            Class::Immutable => IMMUTABLE_CACHE,
            Class::Index => "public, max-age=60",
        };
        assert_eq!(detail.cache_control.as_deref(), Some(cache), "{key}");
    }
    assert_eq!(
        bucket.detail(&history).cache_control.as_deref(),
        Some(IMMUTABLE_CACHE)
    );
    // The bucket holds exactly the repository directory plus the history.
    let mut on_disk = BTreeSet::new();
    files_of(&repo, &repo, &mut on_disk);
    let mut expected: BTreeSet<String> = on_disk.iter().map(|f| format!("packages/{f}")).collect();
    expected.insert(history.clone());
    assert_eq!(bucket.keys(), expected);
    for file in &on_disk {
        assert_eq!(
            bucket.get(&format!("packages/{file}")).unwrap(),
            std::fs::read(repo.join(file)).unwrap(),
            "{file}"
        );
    }
    assert_eq!(
        bucket.get(&history),
        bucket.get(&format!("packages/{CURRENT_PLAN}"))
    );
}

#[test]
fn publishing_again_skips_what_is_there_and_never_goes_back() {
    let Some(bucket) = Bucket::start("publish-again") else {
        return;
    };
    let (target, credentials) = (bucket.target(), bucket.credentials());
    let (_d1, r1, plan1) = repo_of("r1", DATE, &release("1.0.0"));
    publish(&r1, &target, &credentials, &options(DATE)).unwrap();
    // The same plan: already published; its indexes go up again, nothing
    // else.
    let again = publish(&r1, &target, &credentials, &options(DATE)).unwrap();
    assert!(again.already_published);
    let indexes: Vec<String> = plan1
        .files
        .iter()
        .filter(|f| f.class == Class::Index)
        .map(|f| f.path.clone())
        .collect();
    assert_eq!(again.uploaded, indexes);
    // An older plan, or one at the same date: refused, nothing written.
    let before = bucket.keys();
    for (name, date) in [("older", DATE - 60), ("same", DATE)] {
        let mut files = release("1.0.0");
        files[3].1 = b"another key".to_vec();
        let (_d, repo, _) = repo_of(name, date, &files);
        let err = publish(&repo, &target, &credentials, &options(DATE))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("isn't after the published plan's"),
            "{name}: {err}"
        );
    }
    assert_eq!(bucket.keys(), before);
    // The same release later, with a new index: the immutable files are
    // skipped, the indexes go up.
    let mut files = release("1.0.0");
    files[4].1 = b"InRelease 1.0.0, dated later".to_vec();
    let (_d2, r2, plan2) = repo_of("r2", DATE + 60, &files);
    let report = publish(&r2, &target, &credentials, &options(DATE + 60)).unwrap();
    let immutables: Vec<String> = plan2
        .files
        .iter()
        .filter(|f| f.class == Class::Immutable)
        .map(|f| f.path.clone())
        .collect();
    assert_eq!(report.skipped, immutables);
    assert_order(&report, &plan2);
    assert_eq!(
        bucket.get("packages/apt/dists/stable/InRelease").unwrap(),
        b"InRelease 1.0.0, dated later"
    );
}

/// What a test does to a repository directory before publishing it.
type Spoil = dyn Fn(&Path);

#[test]
fn nothing_is_written_when_anything_would_be_refused() {
    let Some(bucket) = Bucket::start("publish-refuse") else {
        return;
    };
    let (target, credentials) = (bucket.target(), bucket.credentials());
    let files = release("1.0.0");
    let (_d, repo, _) = repo_of("r1", DATE, &files);
    // An immutable path already published with other bytes (the same
    // size: only the SHA-256 tells).
    let planted = format!("packages/{}", files[1].0);
    bucket.put(&planted, b"deb 9.9.9");
    let err = publish(&repo, &target, &credentials, &options(DATE))
        .unwrap_err()
        .to_string();
    assert!(err.contains("already published with other bytes"), "{err}");
    assert!(
        err.contains(&format!("{} (other bytes)", files[1].0)),
        "{err}"
    );
    assert_eq!(bucket.keys(), BTreeSet::from([planted.clone()]));
    // A repository directory that isn't its plan's.
    let cases: [(&str, &Spoil, &str); 4] = [
        (
            "extra",
            &|repo| std::fs::write(repo.join("apt/extra.txt"), "x").unwrap(),
            "holds files its plan doesn't list: apt/extra.txt",
        ),
        (
            "shorter",
            &|repo| std::fs::write(repo.join("keys/acme.asc"), "short").unwrap(),
            "isn't the plan's file",
        ),
        (
            "same-size",
            &|repo| {
                let key = repo.join("keys/acme.asc");
                let mut bytes = std::fs::read(&key).unwrap();
                bytes[3] ^= 1;
                std::fs::write(key, bytes).unwrap();
            },
            "changed since its plan was written",
        ),
        (
            "outside",
            &|repo| {
                let mut files = release("1.0.0");
                files.push(("plans/forged.json".into(), b"{}".to_vec(), Class::Index));
                synthetic(repo, DATE, &files);
            },
            "the plan names \"plans/forged.json\"",
        ),
    ];
    for (name, spoil, mentions) in cases {
        let (_d, repo, _) = repo_of(name, DATE, &release("1.0.0"));
        spoil(&repo);
        let err = publish(&repo, &target, &credentials, &options(DATE))
            .unwrap_err()
            .to_string();
        assert!(err.contains(mentions), "{name}: {err}");
    }
    assert_eq!(bucket.keys(), BTreeSet::from([planted]));
}

#[test]
fn pruning_keeps_what_a_plan_referenced_within_the_retention_period() {
    let Some(bucket) = Bucket::start("publish-prune") else {
        return;
    };
    let (target, credentials) = (bucket.target(), bucket.credentials());
    let (_da, ra, plan_a) = repo_of("ra", DATE, &release("1.0.0"));
    let (_db, rb, plan_b) = repo_of("rb", DATE + DAY, &release("1.1.0"));
    publish(&ra, &target, &credentials, &options(DATE)).unwrap();
    // A stray (a publication that failed before its plan went into the
    // history), something else under the prefix, something outside it.
    bucket.put("packages/apt/stray.deb", b"stray");
    bucket.put("packages/notes/readme.txt", b"notes");
    bucket.put("elsewhere/x", b"x");
    let report = publish(&rb, &target, &credentials, &options(DATE + DAY)).unwrap();
    assert!(report.deleted.is_empty(), "{report:?}");
    // Within the retention after B went live, nothing; past it, A's files
    // and the stray (measured from when it was written).
    let real_now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(
        seaworthy::publish::prune(&target, &credentials, real_now + 29 * DAY)
            .unwrap()
            .is_empty()
    );
    let later = real_now.max(DATE + DAY) + 31 * DAY;
    let dry = publish(
        &rb,
        &target,
        &credentials,
        &Options {
            dry_run: true,
            prune: true,
            now: later,
        },
    )
    .unwrap();
    let report = publish(&rb, &target, &credentials, &options(later)).unwrap();
    assert!(report.already_published);
    assert_eq!(dry.deleted, report.deleted, "the dry run previews pruning");
    let a_only: BTreeSet<String> = plan_a
        .files
        .iter()
        .map(|f| f.path.clone())
        .filter(|p| !plan_b.files.iter().any(|f| &f.path == p))
        .collect();
    let mut expected = a_only.clone();
    expected.insert("apt/stray.deb".into());
    assert_eq!(
        report.deleted.iter().cloned().collect::<BTreeSet<_>>(),
        expected
    );
    let keys = bucket.keys();
    for file in &plan_b.files {
        assert!(
            keys.contains(&format!("packages/{}", file.path)),
            "{}",
            file.path
        );
    }
    for kept in ["packages/notes/readme.txt", "elsewhere/x"] {
        assert!(keys.contains(kept), "{kept}");
    }
    assert_eq!(
        keys.iter()
            .filter(|k| k.starts_with("packages/plans/"))
            .count(),
        2,
        "the history stays"
    );
    assert!(
        seaworthy::publish::prune(&target, &credentials, later)
            .unwrap()
            .is_empty()
    );
}

/// What the public URL's stand-in (a proxy in front of the bucket) does.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Proxy {
    Faithful,
    /// Serves `InRelease` with a byte flipped.
    Tampering,
}

/// One HTTP request: method, raw target, headers (names lowercase), body.
type Request = (String, String, Vec<(String, String)>, Vec<u8>);

/// Reads one HTTP request from `stream`.
async fn read_request(stream: &mut tokio::net::TcpStream) -> Option<Request> {
    use tokio::io::AsyncReadExt as _;
    let mut data = Vec::new();
    let mut buf = vec![0_u8; 65536];
    let end = loop {
        if let Some(at) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            break at + 4;
        }
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => data.extend_from_slice(&buf[..n]),
        }
    };
    let head = String::from_utf8_lossy(&data[..end]).to_string();
    let mut lines = head.lines();
    let mut first = lines.next()?.split_whitespace();
    let (method, target) = (first.next()?.to_owned(), first.next()?.to_owned());
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_owned()))
        .collect();
    let length: usize = headers
        .iter()
        .find(|(k, _)| k == "content-length")
        .and_then(|(_, v)| v.parse().ok())
        .unwrap_or(0);
    while data.len() < end + length {
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => data.extend_from_slice(&buf[..n]),
        }
    }
    Some((method, target, headers, data[end..end + length].to_vec()))
}

/// `%XX` decoded.
fn percent_decoded(path: &str) -> String {
    let bytes = path.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            out.push(
                u8::from_str_radix(std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap(), 16).unwrap(),
            );
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

/// A loopback HTTP server answering `GET /packages/<key>?…` from the
/// bucket (percent-decoded, as S3 decodes it); records the raw targets.
fn proxy(bucket: &Bucket, mode: Proxy) -> (String, Arc<Mutex<Vec<String>>>) {
    use tokio::io::AsyncWriteExt as _;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let listener = bucket
        .runtime
        .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let inspect = bucket.inspect.clone();
    let log = seen.clone();
    bucket.runtime.spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let (inspect, log) = (inspect.clone(), log.clone());
            tokio::spawn(async move {
                let Some((_, target, _, _)) = read_request(&mut stream).await else {
                    return;
                };
                log.lock().unwrap().push(target.clone());
                let key = percent_decoded(target.split('?').next().unwrap_or(""));
                let key = key.trim_start_matches('/').to_owned();
                let body = match StoragePath::new(&key) {
                    Ok(path) => inspect
                        .get_object(&path, 1 << 30)
                        .await
                        .ok()
                        .flatten()
                        .map(|o| o.body.to_vec()),
                    Err(_) => None,
                };
                let response = match body {
                    Some(mut body) => {
                        if mode == Proxy::Tampering && key.ends_with("/InRelease") {
                            let middle = body.len() / 2;
                            body[middle] ^= 1;
                        }
                        let mut out = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            body.len()
                        )
                        .into_bytes();
                        out.extend(body);
                        out
                    }
                    None => {
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            .to_vec()
                    }
                };
                let _ = stream.write_all(&response).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (format!("http://127.0.0.1:{port}/packages"), seen)
}

#[test]
fn the_public_url_must_serve_what_was_published() {
    let Some(bucket) = Bucket::start("publish-public") else {
        return;
    };
    let (_d, repo, plan) = repo_of("r1", DATE, &release("1.0.0"));
    let credentials = bucket.credentials();
    let (url, seen) = proxy(&bucket, Proxy::Faithful);
    let mut target = bucket.target();
    target.public_url = Some(url);
    let report = publish(&repo, &target, &credentials, &options(DATE)).unwrap();
    let checked = plan
        .files
        .iter()
        .filter(|f| f.class == Class::Index || f.path.ends_with(".manifest"))
        .count()
        + 1;
    assert_eq!(report.verified, checked);
    let seen = seen.lock().unwrap().clone();
    assert!(
        seen.iter().any(|p| p.contains("1.0.0%2Bb1")),
        "the token's + travels as %2B: {seen:?}"
    );
    assert!(
        seen.iter().all(|p| p.contains("?seaworthy-verify=")),
        "every fetch-back is cache-busted: {seen:?}"
    );
    // A public URL serving something else fails the publication loudly.
    let (lying, _) = proxy(&bucket, Proxy::Tampering);
    target.public_url = Some(lying.clone());
    let err = publish(&repo, &target, &credentials, &options(DATE))
        .unwrap_err()
        .to_string();
    assert!(err.contains("serves other bytes"), "{err}");
    assert!(
        err.contains(&format!("{lying}/apt/dists/stable/InRelease?")),
        "{err}"
    );
    // And one that doesn't answer.
    target.public_url = Some("http://127.0.0.1:9/packages".into());
    let err = publish(&repo, &target, &credentials, &options(DATE))
        .unwrap_err()
        .to_string();
    assert!(err.contains("doesn't serve it"), "{err}");
}

#[test]
fn the_publish_command_reads_its_target_and_credentials() {
    let Some(bucket) = Bucket::start("publish-cli") else {
        return;
    };
    let (dir, repo, _) = repo_of("r1", DATE, &release("1.0.0"));
    let rustfs = bucket.rustfs();
    let target = dir.path().join("publish.toml");
    std::fs::write(
        &target,
        format!(
            "endpoint = \"{}\"\nbucket = \"{}\"\nregion = \"{}\"\nprefix = \"packages\"\n",
            rustfs.endpoint_url, rustfs.bucket, rustfs.region
        ),
    )
    .unwrap();
    let run = |args: &[&str], credentials: bool| {
        let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_seaworthy"));
        command
            .arg("publish")
            .args(args)
            .env_remove("SEAWORTHY_S3_ACCESS_KEY_ID")
            .env_remove("SEAWORTHY_S3_SECRET_ACCESS_KEY")
            .env_remove("SEAWORTHY_S3_SESSION_TOKEN");
        if credentials {
            command
                .env("SEAWORTHY_S3_ACCESS_KEY_ID", rustfs.access_key)
                .env("SEAWORTHY_S3_SECRET_ACCESS_KEY", rustfs.secret_key);
        }
        let out = command.output().unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        (out.status.code(), text)
    };
    let (repo, target) = (repo.to_str().unwrap(), target.to_str().unwrap());
    let (code, text) = run(&["--repo", repo], true);
    assert_eq!(code, Some(2), "{text}");
    assert!(text.contains("publish needs --target"), "{text}");
    let (code, text) = run(&["--repo", repo, "--target", target], false);
    assert_eq!(code, Some(1), "{text}");
    assert!(
        text.contains("SEAWORTHY_S3_ACCESS_KEY_ID is not set"),
        "{text}"
    );
    let (code, text) = run(&["--repo", repo, "--target", target, "--dry-run"], true);
    assert_eq!(code, Some(0), "{text}");
    assert!(
        text.contains("would upload apt/dists/stable/InRelease"),
        "{text}"
    );
    assert!(bucket.keys().is_empty());
    let (code, text) = run(&["--repo", repo, "--target", target], true);
    assert_eq!(code, Some(0), "{text}");
    assert!(text.contains("uploaded publish-plan.json"), "{text}");
    let (code, text) = run(&["--repo", repo, "--target", target], true);
    assert_eq!(code, Some(0), "{text}");
    assert!(text.contains("already published"), "{text}");
    assert!(!text.contains(rustfs.secret_key));
}

#[test]
fn a_signed_repository_from_repo_publishes_byte_for_byte() {
    use common::repo_fixture::{Fixture, TOKEN, tools};
    let Some(nfpm) = tools() else { return };
    let Some(bucket) = Bucket::start("publish-signed") else {
        return;
    };
    // With the repository package, pointing machines at the public
    // URL the publication is checked through.
    let (url, seen) = proxy(&bucket, Proxy::Faithful);
    let fixture = Fixture::with_repository_at(&nfpm, &url);
    let out = fixture.path().join("repo");
    let plan = fixture
        .build_after(&fixture.listings(), &out, common::repo_fixture::DATE, None)
        .unwrap();
    assert_eq!(plan.url.as_deref(), Some(url.as_str()));
    let mut target = bucket.target();
    target.public_url = Some(url);
    let report = publish(
        &out,
        &target,
        &bucket.credentials(),
        &options(common::repo_fixture::DATE),
    )
    .unwrap();
    assert_order(&report, &plan);
    // Every index (the setup/ copies among them), manifest and the plan
    // fetched back through the public URL.
    let seen = seen.lock().unwrap().clone();
    for setup in [
        "/packages/setup/acme-repository.deb?",
        "/packages/setup/acme-repository.deb.asc?",
        "/packages/setup/acme-repository.rpm?",
    ] {
        assert!(
            seen.iter().any(|p| p.starts_with(setup)),
            "{setup}: {seen:?}"
        );
    }
    assert_eq!(
        report.verified,
        plan.files
            .iter()
            .filter(|f| f.class == Class::Index || f.path.ends_with(".manifest"))
            .count()
            + 1
    );
    let mut on_disk = BTreeSet::new();
    files_of(&out, &out, &mut on_disk);
    for file in &on_disk {
        assert_eq!(
            bucket.get(&format!("packages/{file}")).unwrap(),
            std::fs::read(out.join(file)).unwrap(),
            "{file}"
        );
    }
    assert!(bucket.keys().contains(&format!(
        "packages/releases/acme-agent/stable/{TOKEN}/x86_64-unknown-linux-gnu/acme-agent.deb"
    )));
    let setup = bucket.detail("packages/setup/acme-repository.deb");
    assert_eq!(
        setup.cache_control.as_deref(),
        Some("public, max-age=60"),
        "setup/ is replaced by every publication: an index"
    );
    let pool =
        bucket.detail("packages/apt/pool/main/acme-repository/acme-repository_2.1.0-9_all.deb");
    assert_eq!(pool.cache_control.as_deref(), Some(IMMUTABLE_CACHE));
}

// ---------------------------------------------------------------------------
// An in-memory S3 stand-in

#[derive(Clone)]
struct Object {
    body: Vec<u8>,
    content_type: Option<String>,
    cache_control: Option<String>,
    metadata: BTreeMap<String, String>,
}

/// What the stand-in does beyond storing.
#[derive(Default)]
struct Script {
    /// The first create-only PUT of a key ending with this finds it taken
    /// by these bytes (a concurrent writer).
    race: Option<(String, Vec<u8>)>,
    /// A PUT of a key ending with this is refused (403).
    refuse_put: Option<String>,
    /// After this many reads of the current plan, another publication
    /// replaces it.
    move_pointer_after: Option<usize>,
    /// Objects come back without their `Cache-Control`.
    drop_cache_control: bool,
    /// DELETE is refused (403).
    refuse_delete: bool,
    /// A GET of a key ending with this answers these bytes after the
    /// object's (a HEAD still states the object's size).
    longer_get: Option<(String, Vec<u8>)>,
}

/// One logged request: method, key, `If-None-Match`.
type Logged = (String, String, Option<String>);

#[derive(Default)]
struct State {
    objects: BTreeMap<String, Object>,
    pointer_reads: usize,
    requests: Vec<Logged>,
}

/// The stand-in: its endpoint, its state and its script (the runtime
/// serving it lives as long as it does).
struct MemoryS3 {
    _runtime: tokio::runtime::Runtime,
    endpoint: String,
    state: Arc<Mutex<State>>,
    script: Arc<Mutex<Script>>,
}

const BUCKET: &str = "files";

impl MemoryS3 {
    fn start() -> Self {
        use tokio::io::AsyncWriteExt as _;
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let listener = runtime
            .block_on(tokio::net::TcpListener::bind("127.0.0.1:0"))
            .unwrap();
        let endpoint = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let state = Arc::new(Mutex::new(State::default()));
        let script = Arc::new(Mutex::new(Script::default()));
        let (st, sc) = (state.clone(), script.clone());
        runtime.spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let (state, script) = (st.clone(), sc.clone());
                tokio::spawn(async move {
                    while let Some((method, target, headers, body)) =
                        read_request(&mut stream).await
                    {
                        let response = handle(&state, &script, &method, &target, &headers, body);
                        if stream.write_all(&response).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
        Self {
            _runtime: runtime,
            endpoint,
            state,
            script,
        }
    }

    fn target(&self) -> Target {
        Target {
            endpoint: self.endpoint.clone(),
            bucket: BUCKET.into(),
            region: "auto".into(),
            prefix: "packages".into(),
            public_url: None,
            index_max_age_seconds: 60,
            retention_days: 30,
        }
    }

    fn keys(&self) -> BTreeSet<String> {
        self.state.lock().unwrap().objects.keys().cloned().collect()
    }

    fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.state
            .lock()
            .unwrap()
            .objects
            .get(key)
            .map(|o| o.body.clone())
    }

    /// An object put there by something else (no publisher metadata).
    fn plant(&self, key: &str, body: &[u8]) {
        self.state.lock().unwrap().objects.insert(
            key.to_owned(),
            Object {
                body: body.to_vec(),
                content_type: None,
                cache_control: None,
                metadata: BTreeMap::new(),
            },
        );
    }

    fn puts(&self) -> Vec<(String, Option<String>)> {
        self.state
            .lock()
            .unwrap()
            .requests
            .iter()
            .filter(|(m, _, _)| m == "PUT")
            .map(|(_, k, c)| (k.clone(), c.clone()))
            .collect()
    }
}

fn credentials() -> Credentials {
    Credentials::new(
        "AKIDEXAMPLE".into(),
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into(),
        None,
    )
}

fn response(status: &str, headers: &[(String, String)], body: &[u8], head: bool) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\n", body.len());
    for (name, value) in headers {
        out.push_str(&format!("{name}: {value}\r\n"));
    }
    out.push_str("\r\n");
    let mut out = out.into_bytes();
    if !head {
        out.extend_from_slice(body);
    }
    out
}

fn handle(
    state: &Mutex<State>,
    script: &Mutex<Script>,
    method: &str,
    target: &str,
    headers: &[(String, String)],
    body: Vec<u8>,
) -> Vec<u8> {
    let header = |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    };
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let decoded = percent_decoded(path);
    let key = decoded
        .strip_prefix(&format!("/{BUCKET}"))
        .unwrap_or(&decoded)
        .trim_start_matches('/')
        .to_owned();
    let mut state = state.lock().unwrap();
    let mut script = script.lock().unwrap();
    state
        .requests
        .push((method.to_owned(), key.clone(), header("if-none-match")));
    match method {
        "GET" if key.is_empty() => {
            let prefix = query
                .split('&')
                .find_map(|p| p.strip_prefix("prefix="))
                .map(percent_decoded)
                .unwrap_or_default();
            let mut xml = String::from(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult><IsTruncated>false</IsTruncated>",
            );
            for (k, o) in state.objects.range(prefix.clone()..) {
                if !k.starts_with(&prefix) {
                    break;
                }
                xml.push_str(&format!(
                    "<Contents><Key>{k}</Key><LastModified>2026-10-14T12:00:00.000Z</LastModified><ETag>\"e\"</ETag><Size>{}</Size></Contents>",
                    o.body.len()
                ));
            }
            xml.push_str("</ListBucketResult>");
            response("200 OK", &[], xml.as_bytes(), false)
        }
        "GET" | "HEAD" => {
            if method == "GET" && key.ends_with(&format!("/{CURRENT_PLAN}")) {
                state.pointer_reads += 1;
                if script
                    .move_pointer_after
                    .is_some_and(|n| state.pointer_reads > n)
                {
                    let moved = Plan {
                        repository: "acme".into(),
                        channel: "stable".into(),
                        url: None,
                        rollback: false,
                        date: DATE + 365 * DAY,
                        releases: Vec::new(),
                        tools: BTreeMap::new(),
                        files: Vec::new(),
                    };
                    state.objects.insert(
                        key.clone(),
                        Object {
                            body: serde_json::to_vec_pretty(&moved).unwrap(),
                            content_type: None,
                            cache_control: None,
                            metadata: BTreeMap::new(),
                        },
                    );
                    script.move_pointer_after = None;
                }
            }
            let Some(object) = state.objects.get(&key) else {
                return response("404 Not Found", &[], b"", false);
            };
            let mut out = vec![
                ("ETag".to_owned(), "\"e\"".to_owned()),
                (
                    "Last-Modified".to_owned(),
                    "Wed, 14 Oct 2026 12:00:00 GMT".to_owned(),
                ),
            ];
            if let Some(t) = &object.content_type {
                out.push(("Content-Type".to_owned(), t.clone()));
            }
            if let Some(c) = &object.cache_control
                && !script.drop_cache_control
            {
                out.push(("Cache-Control".to_owned(), c.clone()));
            }
            for (k, v) in &object.metadata {
                out.push((format!("x-amz-meta-{k}"), v.clone()));
            }
            if method == "GET"
                && let Some((suffix, extra)) = &script.longer_get
                && key.ends_with(suffix.as_str())
            {
                let mut body = object.body.clone();
                body.extend_from_slice(extra);
                return response("200 OK", &out, &body, false);
            }
            response("200 OK", &out, &object.body, method == "HEAD")
        }
        "PUT" => {
            if script
                .refuse_put
                .as_deref()
                .is_some_and(|suffix| key.ends_with(suffix))
            {
                return response("403 Forbidden", &[], b"", false);
            }
            if header("if-none-match").as_deref() == Some("*") {
                if let Some((suffix, racer)) = script.race.clone()
                    && key.ends_with(&suffix)
                {
                    script.race = None;
                    state.objects.insert(
                        key.clone(),
                        Object {
                            body: racer.clone(),
                            content_type: None,
                            cache_control: None,
                            metadata: [(
                                "sha256".to_owned(),
                                seaworthy_crypto::digest::sha256_hex(&racer),
                            )]
                            .into(),
                        },
                    );
                }
                if state.objects.contains_key(&key) {
                    return response("412 Precondition Failed", &[], b"", false);
                }
            }
            let metadata = headers
                .iter()
                .filter_map(|(k, v)| Some((k.strip_prefix("x-amz-meta-")?.to_owned(), v.clone())))
                .collect();
            state.objects.insert(
                key,
                Object {
                    body,
                    content_type: header("content-type"),
                    cache_control: header("cache-control"),
                    metadata,
                },
            );
            response("200 OK", &[], b"", false)
        }
        "DELETE" => {
            if script.refuse_delete {
                return response("403 Forbidden", &[], b"", false);
            }
            state.objects.remove(&key);
            response("204 No Content", &[], b"", false)
        }
        _ => response("405 Method Not Allowed", &[], b"", false),
    }
}

#[test]
fn an_immutable_file_raced_into_place_must_be_the_same_bytes() {
    let files = release("1.0.0");
    let (_d, repo, plan) = repo_of("r1", DATE, &files);
    let first = &plan.files[0];
    let no_prune = Options {
        dry_run: false,
        prune: false,
        now: DATE,
    };
    // Another writer's bytes: refused, and nothing after it uploaded.
    let s3 = MemoryS3::start();
    s3.script.lock().unwrap().race = Some((first.path.clone(), b"other bytes".to_vec()));
    let err = publish(&repo, &s3.target(), &credentials(), &no_prune)
        .unwrap_err()
        .to_string();
    assert!(
        err.contains(&format!(
            "{} was published with other bytes while this publication ran",
            first.path
        )),
        "{err}"
    );
    assert_eq!(
        s3.puts(),
        [(format!("packages/{}", first.path), Some("*".to_owned()))],
        "immutable files go up create-only; nothing after the refusal"
    );
    // The same bytes (a concurrent publication of the same plan): fine;
    // every immutable PUT create-only, every index PUT not.
    let s3 = MemoryS3::start();
    s3.script.lock().unwrap().race = Some((first.path.clone(), files[0].1.clone()));
    publish(&repo, &s3.target(), &credentials(), &no_prune).unwrap();
    let puts = s3.puts();
    for file in &plan.files {
        let put = puts
            .iter()
            .find(|(k, _)| *k == format!("packages/{}", file.path))
            .unwrap_or_else(|| panic!("{} wasn't uploaded: {puts:?}", file.path));
        assert_eq!(
            put.1.is_some(),
            file.class == Class::Immutable,
            "{}",
            file.path
        );
    }
}

#[test]
fn a_publication_stopped_midway_is_resumed_never_rolled_back() {
    // B's history went in, then an index upload failed: B may be
    // live. A re-run of A (the pointer's) must not roll it back, pruning
    // must keep both, and B's re-run finishes it.
    let s3 = MemoryS3::start();
    let target = s3.target();
    let (_da, ra, plan_a) = repo_of("ra", DATE, &release("1.0.0"));
    let (_db, rb, plan_b) = repo_of("rb", DATE + DAY, &release("1.1.0"));
    publish(&ra, &target, &credentials(), &options(DATE)).unwrap();
    s3.script.lock().unwrap().refuse_put = Some("repodata/repomd.xml".into());
    let err = publish(&rb, &target, &credentials(), &options(DATE + DAY))
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("uploading rpm/stable/x86_64/repodata/repomd.xml"),
        "{err}"
    );
    assert_eq!(
        s3.keys()
            .iter()
            .filter(|k| k.starts_with("packages/plans/"))
            .count(),
        2,
        "B went into the history before its indexes"
    );
    assert_eq!(
        s3.get("packages/apt/dists/stable/InRelease").unwrap(),
        b"InRelease 1.1.0",
        "B's first index is live"
    );
    let a_bytes = std::fs::read(ra.join(seaworthy::repo::PLAN_FILE)).unwrap();
    assert_eq!(
        s3.get(&format!("packages/{CURRENT_PLAN}")).unwrap(),
        a_bytes
    );
    s3.script.lock().unwrap().refuse_put = None;
    // A again: refused, not rolled back.
    let err = publish(&ra, &target, &credentials(), &options(DATE + DAY))
        .unwrap_err()
        .to_string();
    assert!(err.contains("a newer plan"), "{err}");
    assert_eq!(
        s3.get("packages/apt/dists/stable/InRelease").unwrap(),
        b"InRelease 1.1.0"
    );
    // Pruning, however late: A's files are the current plan's, B's are in
    // the history with nothing after them.
    assert!(
        seaworthy::publish::prune(&target, &credentials(), DATE + 1000 * DAY)
            .unwrap()
            .is_empty()
    );
    // B's re-run finishes it: immutable files skipped, its history kept,
    // the indexes and the pointer up.
    let report = publish(&rb, &target, &credentials(), &options(DATE + DAY)).unwrap();
    assert!(!report.already_published);
    let immutables: Vec<String> = plan_b
        .files
        .iter()
        .filter(|f| f.class == Class::Immutable)
        .map(|f| f.path.clone())
        .collect();
    assert_eq!(report.skipped, immutables);
    let b_bytes = std::fs::read(rb.join(seaworthy::repo::PLAN_FILE)).unwrap();
    assert_eq!(
        s3.get(&format!("packages/{CURRENT_PLAN}")).unwrap(),
        b_bytes
    );
    assert_eq!(
        s3.get("packages/rpm/stable/x86_64/repodata/repomd.xml")
            .unwrap(),
        b"<repomd 1.1.0/>"
    );
    let keys = s3.keys();
    assert!(
        plan_a
            .files
            .iter()
            .all(|f| keys.contains(&format!("packages/{}", f.path)))
    );
}

#[test]
fn another_publication_moving_the_current_plan_stops_this_one() {
    let s3 = MemoryS3::start();
    let (_d, repo, _) = repo_of("r1", DATE, &release("1.0.0"));
    s3.script.lock().unwrap().move_pointer_after = Some(1);
    let err = publish(&repo, &s3.target(), &credentials(), &options(DATE))
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("another publication replaced publish-plan.json"),
        "{err}"
    );
    let ours = std::fs::read(repo.join(seaworthy::repo::PLAN_FILE)).unwrap();
    assert_ne!(s3.get(&format!("packages/{CURRENT_PLAN}")).unwrap(), ours);
}

#[test]
fn a_store_that_doesnt_keep_what_was_sent_is_caught() {
    let s3 = MemoryS3::start();
    s3.script.lock().unwrap().drop_cache_control = true;
    let (_d, repo, plan) = repo_of("r1", DATE, &release("1.0.0"));
    let err = publish(&repo, &s3.target(), &credentials(), &options(DATE))
        .unwrap_err()
        .to_string();
    assert!(
        err.contains(&format!(
            "the store didn't keep {} as sent",
            plan.files[0].path
        )),
        "{err}"
    );
    assert_eq!(s3.puts().len(), 1, "stopped at the first upload");
}

#[test]
fn the_repository_package_must_point_where_the_publication_goes() {
    // a plan whose repository package points machines at a URL is
    // published only to a target that names it as its public URL (and is
    // checked from there); anything else is refused before any request.
    let s3 = MemoryS3::start();
    let (_d, repo, mut plan) = repo_of("r1", DATE, &release("1.0.0"));
    plan.url = Some("https://packages.acme.test/repo".into());
    std::fs::write(
        repo.join("publish-plan.json"),
        serde_json::to_vec_pretty(&plan).unwrap(),
    )
    .unwrap();
    let mut target = s3.target();
    let refused = |target: &Target, mentions: &str| {
        let err = publish(&repo, target, &credentials(), &options(DATE))
            .unwrap_err()
            .to_string();
        assert!(err.contains(mentions), "{mentions}: {err}");
    };
    refused(
        &target,
        "the repository package points machines at https://packages.acme.test/repo: publish.toml must name it as public-url",
    );
    target.public_url = Some("https://files.acme.test/repo".into());
    refused(
        &target,
        "but publish.toml's public-url is https://files.acme.test/repo",
    );
    assert!(
        s3.state.lock().unwrap().requests.is_empty(),
        "refused before any request"
    );
}

#[test]
fn objects_without_the_publishers_metadata_are_compared_by_their_bytes() {
    let files = release("1.0.0");
    let (_d, repo, _) = repo_of("r1", DATE, &files);
    // The same bytes, put there by something else: read, hashed, skipped.
    let s3 = MemoryS3::start();
    s3.plant(&format!("packages/{}", files[0].0), &files[0].1);
    let report = publish(&repo, &s3.target(), &credentials(), &options(DATE)).unwrap();
    assert_eq!(report.skipped, [files[0].0.clone()]);
    // Other bytes of the same size: refused.
    let s3 = MemoryS3::start();
    let mut other = files[0].1.clone();
    other[0] ^= 1;
    s3.plant(&format!("packages/{}", files[0].0), &other);
    let err = publish(&repo, &s3.target(), &credentials(), &options(DATE))
        .unwrap_err()
        .to_string();
    assert!(
        err.contains(&format!("{} (other bytes)", files[0].0)),
        "{err}"
    );
    // Another size: refused without reading it.
    let s3 = MemoryS3::start();
    s3.plant(&format!("packages/{}", files[0].0), b"x");
    let err = publish(&repo, &s3.target(), &credentials(), &options(DATE))
        .unwrap_err()
        .to_string();
    assert!(err.contains(&format!("{} (1 bytes)", files[0].0)), "{err}");
    // The size its HEAD states, but a body running past it: refused, and
    // nothing uploaded.
    let s3 = MemoryS3::start();
    s3.plant(&format!("packages/{}", files[0].0), &files[0].1);
    s3.script.lock().unwrap().longer_get = Some((files[0].0.clone(), vec![b'x'; 70_000]));
    let err = publish(&repo, &s3.target(), &credentials(), &options(DATE))
        .unwrap_err()
        .to_string();
    assert!(
        err.contains(&format!(
            "{} (more than its {} bytes when read)",
            files[0].0,
            files[0].1.len()
        )),
        "{err}"
    );
    assert!(s3.puts().is_empty(), "{:?}", s3.puts());
}

#[test]
fn a_pruning_failure_is_reported_apart_and_foreign_keys_are_left() {
    let s3 = MemoryS3::start();
    let target = s3.target();
    let (_da, ra, _) = repo_of("ra", DATE, &release("1.0.0"));
    let (_db, rb, _) = repo_of("rb", DATE + DAY, &release("1.1.0"));
    publish(&ra, &target, &credentials(), &options(DATE)).unwrap();
    publish(&rb, &target, &credentials(), &options(DATE + DAY)).unwrap();
    // Not a key this publisher writes (a Windows device name).
    s3.plant("packages/apt/zz/CON", b"foreign");
    let later = DATE + 40 * DAY;
    s3.script.lock().unwrap().refuse_delete = true;
    let report = publish(&rb, &target, &credentials(), &options(later)).unwrap();
    assert!(report.already_published);
    let why = report
        .prune_error
        .expect("a refused delete is a pruning failure");
    assert!(why.contains("deleting"), "{why}");
    assert_eq!(report.foreign, ["apt/zz/CON"]);
    s3.script.lock().unwrap().refuse_delete = false;
    let report = publish(&rb, &target, &credentials(), &options(later)).unwrap();
    assert!(report.prune_error.is_none());
    assert_eq!(report.deleted.len(), 3, "{report:?}");
    assert!(s3.keys().contains("packages/apt/zz/CON"));
}
