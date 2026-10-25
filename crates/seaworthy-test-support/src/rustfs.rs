//! RustFS standalone S3 for the publisher's live-store suites: real SigV4,
//! real conditional writes (`If-None-Match: *`), real
//! `x-amz-checksum-sha256` verification, real ETags and user metadata, no
//! external cloud credentials required. (MinIO's successor for self-hosted
//! test backends.)
//!
//! The `mkdir` bootstrap below creates PLAIN buckets (a bucket is a
//! directory in RustFS's fs layout).

use testcontainers::{
    ContainerAsync, GenericImage,
    core::{ContainerPort, ExecCommand, ImageExt as _, WaitFor},
};

use crate::{dind, images, split_image};

/// Static credentials for the throwaway instance: deliberately NOT
/// rustfs's documented defaults (the image warns loudly on the default
/// pair). Throwaway test constants, never a secret.
pub const RUSTFS_ACCESS_KEY: &str = "seaworthy-test-access";
/// The secret half.
pub const RUSTFS_SECRET_KEY: &str = "seaworthy-test-secret";

/// The most buckets one [`start_rustfs_with_buckets`] creates (a test
/// fixture, not a tenancy model).
pub const MAX_RUSTFS_BUCKETS: usize = 16;

/// A running RustFS with its buckets created, plus the containers (kept
/// alive by ownership).
pub struct Rustfs {
    /// `http://localhost:{port}`: the S3 endpoint URL (via the dind relay
    /// when the tests run inside a container; direct otherwise).
    pub endpoint_url: String,
    /// The region the backend config should use (path-style endpoint).
    pub region: &'static str,
    /// The (first) pre-created bucket.
    pub bucket: String,
    /// Every pre-created bucket, in the order asked
    /// ([`start_rustfs_with_buckets`]; `[bucket]` for [`start_rustfs`]).
    pub buckets: Vec<String>,
    /// [`RUSTFS_ACCESS_KEY`].
    pub access_key: &'static str,
    /// [`RUSTFS_SECRET_KEY`].
    pub secret_key: &'static str,
    _container: ContainerAsync<GenericImage>,
    _relay: Option<crate::dind::LocalhostRelay>,
}

impl Rustfs {
    /// The container ids this struct keeps alive.
    #[must_use]
    pub fn container_ids(&self) -> Vec<String> {
        vec![self._container.id().to_string()]
    }
}

/// Defense-in-depth on the bucket name: it interpolates into the
/// in-container `mkdir -p /data/{bucket}` argv. The argv form already makes
/// shell injection unrepresentable (no shell runs), but the S3 charset gate
/// also kills path tricks (`..`, `/`) and argv tricks (a leading `-`
/// reading as a mkdir flag) at the boundary: in-repo constants today, but
/// the parameter is a `&str` any caller can fill.
fn validate_bucket_name(bucket: &str) {
    assert!(
        !bucket.is_empty()
            && bucket.len() <= 63
            && bucket
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !bucket.starts_with('-'),
        "rustfs bucket name {bucket:?} must be 1–63 chars of [a-z0-9-] and not start with '-' \
         (it interpolates into the container's mkdir argv)"
    );
}

/// The bucket list gate: 1..=[`MAX_RUSTFS_BUCKETS`] distinct names, each
/// through [`validate_bucket_name`], before any container starts.
fn validate_bucket_list(buckets: &[&str]) {
    assert!(
        (1..=MAX_RUSTFS_BUCKETS).contains(&buckets.len()),
        "start_rustfs_with_buckets takes 1..={MAX_RUSTFS_BUCKETS} buckets, got {}",
        buckets.len()
    );
    for (at, bucket) in buckets.iter().enumerate() {
        validate_bucket_name(bucket);
        assert!(
            !buckets[..at].contains(bucket),
            "rustfs bucket {bucket:?} is named twice"
        );
    }
}

/// Start RustFS and create `bucket`. CALL `docker_or_skip` first.
///
/// Bucket bootstrap: RustFS keeps MinIO's standalone fs layout (a bucket
/// is a directory under the data root), so an in-container `mkdir` is the
/// dependency-free create (no `mc` sidecar, no SDK).
pub async fn start_rustfs(bucket: &str) -> Rustfs {
    start_rustfs_with_buckets(&[bucket]).await
}

/// Start RustFS and create every bucket of `buckets` (a caller with several
/// buckets, e.g. one per publication target, tests against one container).
/// CALL `docker_or_skip` first. Each name passes the same charset gate as
/// [`start_rustfs`]'s; the list is 1..=[`MAX_RUSTFS_BUCKETS`] distinct
/// names (anything else panics: a fixture bug). One in-container `mkdir`
/// creates them all.
pub async fn start_rustfs_with_buckets(buckets: &[&str]) -> Rustfs {
    validate_bucket_list(buckets);
    let (name, tag) = split_image(images::RUSTFS);
    let container = crate::launch::start("rustfs", None, &[], || {
        GenericImage::new(name, tag)
            .with_wait_for(WaitFor::http(
                testcontainers::core::wait::HttpWaitStrategy::new("/health/ready")
                    .with_port(ContainerPort::Tcp(9000))
                    .with_expected_status_code(200u16),
            ))
            // Mapped (not just exposed): an explicit binding exists for the
            // launch path's publish pin to rewrite.
            .with_mapped_port(0, ContainerPort::Tcp(9000))
            .with_env_var("RUSTFS_ACCESS_KEY", RUSTFS_ACCESS_KEY)
            .with_env_var("RUSTFS_SECRET_KEY", RUSTFS_SECRET_KEY)
    })
    .await;
    let port = container
        .get_host_port_ipv4(ContainerPort::Tcp(9000))
        .await
        .expect("rustfs port");

    let mut argv = vec!["mkdir".to_owned(), "-p".to_owned()];
    argv.extend(buckets.iter().map(|bucket| format!("/data/{bucket}")));
    let mut result = container
        .exec(ExecCommand::new(argv))
        .await
        .expect("bucket bootstrap exec failed");
    // Consuming stdout blocks until the command exits; the exit code is
    // only inspectable afterwards.
    let _ = result.stdout_to_vec().await.expect("mkdir stdout");
    assert_eq!(
        result.exit_code().await.expect("exec exit code"),
        Some(0),
        "bucket bootstrap mkdir failed"
    );

    let relay = dind::localhost_relay(port).await;
    Rustfs {
        endpoint_url: format!("http://localhost:{}", relay.local_port),
        region: "us-east-1",
        bucket: buckets[0].to_string(),
        buckets: buckets.iter().map(|bucket| (*bucket).to_string()).collect(),
        access_key: RUSTFS_ACCESS_KEY,
        secret_key: RUSTFS_SECRET_KEY,
        _container: container,
        _relay: relay.guard,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn bucket_names_accept_the_s3_charset() {
        for name in ["bucket", "a", "acme-test-123", "0-9"] {
            super::validate_bucket_name(name);
        }
    }

    #[test]
    fn bucket_names_reject_everything_else() {
        // The name interpolates into the in-container `mkdir -p /data/{bucket}`
        // argv: argv-form already kills shell injection; the charset gate is
        // the defense-in-depth against path/argv tricks (`..`, `/`, flags).
        for name in [
            "",
            "has space",
            "UPPER",
            "../escape",
            "a/b",
            "-starts-like-a-flag",
            "dots.not.allowed",
            "under_score",
            "semi;colon",
            "new\nline",
        ] {
            assert!(
                std::panic::catch_unwind(|| super::validate_bucket_name(name)).is_err(),
                "{name:?} must be rejected"
            );
        }
    }

    #[test]
    fn a_bucket_list_is_bounded_distinct_and_canonical() {
        super::validate_bucket_list(&["acme-packages", "acme-releases", "acme-keys"]);
        let names: Vec<String> = (0..super::MAX_RUSTFS_BUCKETS)
            .map(|n| format!("b{n}"))
            .collect();
        super::validate_bucket_list(&names.iter().map(String::as_str).collect::<Vec<_>>());
        let too_many: Vec<String> = (0..=super::MAX_RUSTFS_BUCKETS)
            .map(|n| format!("b{n}"))
            .collect();
        let too_many: Vec<&str> = too_many.iter().map(String::as_str).collect();
        for bad in [
            &[][..],
            &["twice", "twice"][..],
            &["fine", "../escape"][..],
            &too_many[..],
        ] {
            assert!(
                std::panic::catch_unwind(|| super::validate_bucket_list(bad)).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }
}
