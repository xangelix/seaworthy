//! Direct, server-side object writes and reads: an in-memory `PutObject`
//! that is CREATE-ONLY on request (`If-None-Match: *`) and always carries
//! an in-module SHA-256 `x-amz-checksum-sha256`, and a bounded,
//! checksum-verified `GetObject`. Why each piece:
//!
//! - **Create-only** makes a retried write idempotent without ever
//!   overwriting: a second `PUT` of an existing key answers
//!   [`PutOutcome::AlreadyExists`] (S3 `412 PreconditionFailed`), and the
//!   caller decides: the same bytes are success, different bytes are an
//!   alarm (a published file is immutable). A concurrent conditional write
//!   (`409 ConditionalRequestConflict`) is retryable.
//! - **Replace-if-unchanged** (`If-Match: <ETag>`) moves a pointer only
//!   from the version the caller read: another writer's version answers
//!   [`PutOutcome::Changed`] and nothing is written. A `412` is a
//!   condition's answer only: an unconditional write that gets one is an
//!   error, never taken for success.
//! - **The checksum on every write**: SHA-256 stays inside the FIPS module
//!   (no MD5 in the facade). The service verifies it against the body
//!   (`BadDigest` otherwise) and stores it, and a read with
//!   `x-amz-checksum-mode: ENABLED` echoes it: [`S3Backend::get_object`]
//!   re-verifies the body against it.
//! - **Bounded**: a put carries at most [`PutOptions::max_body_bytes`]
//!   (64 MiB unless raised, never past S3's single-request limit) under its
//!   own deadline; a get buffers at most the caller's `max_bytes`, refusing
//!   an oversized answer before buffering it.

use std::collections::BTreeMap;
use std::time::Duration;

use bytes::Bytes;
use futures_util::StreamExt as _;

use super::{
    MIN_DURATION_KNOB, S3Backend, StorageError, StoragePath, b64, checksum_matches,
    validate_content_type, validate_header_value,
};

/// The largest body [`S3Backend::put_object`] sends by default (64 MiB):
/// in-memory objects; anything bigger needs the caller to raise the cap
/// ([`PutOptions::with_max_body_bytes`]).
pub const MAX_DIRECT_OBJECT_BYTES: u64 = 64 * 1024 * 1024;

/// The most one `PutObject` may carry: S3's single-request limit (5 GiB).
/// A caller that raises [`PutOptions::max_body_bytes`] holds the body in
/// memory; in exchange the object keeps a full-object SHA-256 (a multipart
/// upload stores a checksum of part checksums instead).
pub const MAX_SINGLE_PUT_BYTES: u64 = 5 * 1024 * 1024 * 1024;

/// User metadata travels as `x-amz-meta-<name>` headers.
pub const USER_METADATA_PREFIX: &str = "x-amz-meta-";

/// The most user metadata entries one put carries (S3 allows 2 KiB in all).
pub const MAX_USER_METADATA: usize = 8;

/// The longest deadline a single put, or a streamed read
/// ([`S3Backend::get_stream`]), may ask for: the slowest plausible
/// transfer of [`MAX_SINGLE_PUT_BYTES`] still ends.
pub const MAX_PUT_TIMEOUT: Duration = Duration::from_secs(6 * 3600);

/// How [`S3Backend::put_object`] writes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PutOptions {
    /// The stored `Content-Type` (validated: a header-safe
    /// `type/subtype[; params]`).
    pub content_type: String,
    /// Send `If-None-Match: *`: the write succeeds only when the key has no
    /// current object (a second write answers
    /// [`PutOutcome::AlreadyExists`], never overwrites).
    pub create_only: bool,
    /// The stored `Cache-Control` (`None`: the service's default): what a
    /// CDN or proxy in front of the bucket honours (a published package's
    /// `public, max-age=31536000, immutable`).
    pub cache_control: Option<String>,
    /// The largest body this put accepts: [`MAX_DIRECT_OBJECT_BYTES`] by
    /// default, at most [`MAX_SINGLE_PUT_BYTES`].
    pub max_body_bytes: u64,
    /// User metadata (`x-amz-meta-<name>`), signed into the request: at
    /// most [`MAX_USER_METADATA`] entries, names `[a-z0-9-]{1,64}`, values
    /// as every signed header value. Every S3-compatible store keeps and
    /// returns it ([`S3Backend::head_object_detail`]).
    pub metadata: Vec<(String, String)>,
    /// The put's deadline (`None`: the management deadline). A large body
    /// needs longer than any management call: scale it with the size. At
    /// most [`MAX_PUT_TIMEOUT`].
    pub timeout: Option<Duration>,
    /// Send `If-Match: <ETag>`: the write replaces only the version with
    /// this ETag (as [`FetchedObject::etag`] or
    /// [`ObjectDetail::etag`] gave it, quotes included); another version,
    /// or none, answers [`PutOutcome::Changed`]. Never with
    /// [`create_only`](Self::create_only).
    pub if_match: Option<String>,
}

impl PutOptions {
    /// Create-only, `application/octet-stream`: the write-once shape.
    #[must_use]
    pub fn create_only() -> Self {
        Self {
            content_type: super::DEFAULT_CONTENT_TYPE.to_owned(),
            create_only: true,
            cache_control: None,
            max_body_bytes: MAX_DIRECT_OBJECT_BYTES,
            metadata: Vec::new(),
            timeout: None,
            if_match: None,
        }
    }

    /// Replace only the version whose ETag is `etag` (`If-Match`), and so
    /// not create-only.
    #[must_use]
    pub fn with_if_match(mut self, etag: impl Into<String>) -> Self {
        self.if_match = Some(etag.into());
        self.create_only = false;
        self
    }

    /// Add a user metadata entry (`x-amz-meta-<name>: <value>`).
    #[must_use]
    pub fn with_metadata(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.push((name.into(), value.into()));
        self
    }

    /// Set the put's deadline (at most [`MAX_PUT_TIMEOUT`]).
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set the stored `Cache-Control` (validated: 1..=255 printable ASCII
    /// bytes, as every signed header value).
    #[must_use]
    pub fn with_cache_control(mut self, cache_control: impl Into<String>) -> Self {
        self.cache_control = Some(cache_control.into());
        self
    }

    /// Raise (or lower) the body cap, up to [`MAX_SINGLE_PUT_BYTES`]: one
    /// request, one full-object checksum, the whole body in memory.
    #[must_use]
    pub const fn with_max_body_bytes(mut self, max_body_bytes: u64) -> Self {
        self.max_body_bytes = max_body_bytes;
        self
    }

    /// Set the stored content type.
    #[must_use]
    pub fn with_content_type(mut self, content_type: impl Into<String>) -> Self {
        self.content_type = content_type.into();
        self
    }
}

/// What a [`S3Backend::put_object`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PutOutcome {
    /// The object was written.
    Created {
        /// The ETag the service answered, when it sent one.
        etag: Option<String>,
        /// The new version's id (`x-amz-version-id`) on a versioned bucket.
        version_id: Option<String>,
    },
    /// A create-only write found the key already present (S3 `412
    /// PreconditionFailed`): NOTHING was written. Read the existing object
    /// ([`S3Backend::get_object`], [`S3Backend::head_object_detail`]) to
    /// decide whether it is the same bytes.
    AlreadyExists,
    /// An `If-Match` write ([`PutOptions::if_match`]) found another version
    /// of the object, or none (S3 `412 PreconditionFailed`, or `404`):
    /// NOTHING was written.
    Changed,
}

/// What [`S3Backend::head_object_detail`] reports about an object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectDetail {
    /// The size in bytes.
    pub size: u64,
    /// The ETag (verbatim, quotes preserved).
    pub etag: Option<String>,
    /// The modification time, as the service sends it (an HTTP date).
    pub last_modified: Option<String>,
    /// The stored `Content-Type`.
    pub content_type: Option<String>,
    /// The stored `Cache-Control`.
    pub cache_control: Option<String>,
    /// The stored full-object SHA-256, base64 (`None`: none stored, or a
    /// multipart object's composite checksum).
    pub sha256: Option<String>,
    /// The user metadata, by name (without `x-amz-meta-`).
    pub metadata: BTreeMap<String, String>,
}

/// An object read by [`S3Backend::get_object`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchedObject {
    /// The whole body (bounded by the call's `max_bytes`).
    pub body: Bytes,
    /// The version read (`x-amz-version-id`), on a versioned bucket.
    pub version_id: Option<String>,
    /// The ETag.
    pub etag: Option<String>,
    /// The stored `x-amz-checksum-sha256`, when the service reported one
    /// (the body was verified against it).
    pub checksum_sha256: Option<String>,
}

/// A response header as text.
fn header(response: &reqwest::Response, name: &str) -> Option<String> {
    response
        .headers()
        .get(name)
        .and_then(|h| h.to_str().ok())
        .map(str::to_owned)
}

/// Whether `len` bytes exceed `cap` (a `usize` that does not fit `u64`
/// exceeds every cap).
fn exceeds(len: usize, cap: u64) -> bool {
    u64::try_from(len).map_or(true, |len| len > cap)
}

/// Whether `error` is S3's `412 PreconditionFailed`.
fn is_precondition_failed(error: &StorageError) -> bool {
    match error {
        StorageError::S3 { code, .. } => code == "PreconditionFailed",
        StorageError::Http { status_code, .. } => *status_code == 412,
        _ => false,
    }
}

/// Whether `error` is S3's `404` (no such key).
fn is_not_found(error: &StorageError) -> bool {
    match error {
        StorageError::S3 { code, .. } => code == "NoSuchKey" || code == "NotFound",
        StorageError::Http { status_code, .. } => *status_code == 404,
        _ => false,
    }
}

impl S3Backend {
    /// `PutObject` of an in-memory body (≤ [`PutOptions::max_body_bytes`],
    /// [`MAX_DIRECT_OBJECT_BYTES`] by default), header-signed: the body's
    /// SHA-256 (computed in-module) rides `x-amz-checksum-sha256` on EVERY
    /// write (the service refuses a body that does not match it) plus, per
    /// `options`, `If-None-Match: *` (create-only) or `If-Match`, the stored
    /// type, cache rule and user metadata, all signed. A service-echoed checksum is
    /// re-checked. Every option is validated before any request is sent.
    ///
    /// # Errors
    /// [`StorageError::Validation`] for an oversized body, an unusable
    /// content type, cache rule, ETag or metadata entry, both conditions,
    /// or a deadline out of range; [`StorageError::HashMismatch`] when the service echoes a
    /// different checksum; request failures otherwise (`409
    /// ConditionalRequestConflict` is retryable:
    /// [`StorageError::is_retryable`]).
    pub async fn put_object(
        &self,
        path: &StoragePath,
        body: Bytes,
        options: &PutOptions,
    ) -> Result<PutOutcome, StorageError> {
        if options.max_body_bytes > MAX_SINGLE_PUT_BYTES {
            return Err(StorageError::Validation(format!(
                "a single put carries at most {MAX_SINGLE_PUT_BYTES} bytes (S3's limit)"
            )));
        }
        if exceeds(body.len(), options.max_body_bytes) {
            return Err(StorageError::Validation(format!(
                "a direct put carries at most {} bytes, got {}",
                options.max_body_bytes,
                body.len()
            )));
        }
        validate_content_type(&options.content_type)?;
        if let Some(etag) = &options.if_match {
            if options.create_only {
                return Err(StorageError::Validation(
                    "a put is create-only or If-Match, never both".to_owned(),
                ));
            }
            validate_header_value(etag, "an If-Match ETag")?;
        }
        if let Some(cache_control) = &options.cache_control {
            validate_header_value(cache_control, "a Cache-Control value")?;
        }
        if options.metadata.len() > MAX_USER_METADATA {
            return Err(StorageError::Validation(format!(
                "at most {MAX_USER_METADATA} user metadata entries"
            )));
        }
        let mut names = std::collections::BTreeSet::new();
        for (name, value) in &options.metadata {
            let well_formed = !name.is_empty()
                && name.len() <= 64
                && name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
            if !well_formed || !names.insert(name.as_str()) {
                return Err(StorageError::Validation(format!(
                    "user metadata name {name:?} must be [a-z0-9-]{{1,64}}, once"
                )));
            }
            validate_header_value(value, "a user metadata value")?;
        }
        if options
            .timeout
            .is_some_and(|t| t > MAX_PUT_TIMEOUT || t.is_zero())
        {
            return Err(StorageError::Validation(format!(
                "a put's deadline must be between 1 ns and {} s",
                MAX_PUT_TIMEOUT.as_secs()
            )));
        }
        let digest = seaworthy_crypto::digest::sha256(&body);
        let mut headers = vec![
            ("content-type".to_owned(), options.content_type.clone()),
            ("x-amz-checksum-sha256".to_owned(), b64(&digest)),
            (
                "x-amz-sdk-checksum-algorithm".to_owned(),
                "SHA256".to_owned(),
            ),
        ];
        if let Some(cache_control) = &options.cache_control {
            headers.push(("cache-control".to_owned(), cache_control.clone()));
        }
        for (name, value) in &options.metadata {
            headers.push((format!("{USER_METADATA_PREFIX}{name}"), value.clone()));
        }
        if options.create_only {
            headers.push(("if-none-match".to_owned(), "*".to_owned()));
        }
        if let Some(etag) = &options.if_match {
            headers.push(("if-match".to_owned(), etag.clone()));
        }
        let deadline = options.timeout.unwrap_or(self.config.management_timeout);
        let result = self
            .management_request_within("PUT", path, headers, body, deadline)
            .await;
        let response = match result {
            Ok(response) => response,
            // A 412 is a condition's answer: what it means depends on the
            // condition sent, and without one it's an error like any other.
            Err(error) if is_precondition_failed(&error) && options.create_only => {
                return Ok(PutOutcome::AlreadyExists);
            }
            Err(error)
                if options.if_match.is_some()
                    && (is_precondition_failed(&error) || is_not_found(&error)) =>
            {
                return Ok(PutOutcome::Changed);
            }
            Err(error) => return Err(error),
        };
        if let Some(echoed) = header(&response, "x-amz-checksum-sha256")
            && !checksum_matches(&echoed, &digest)
        {
            return Err(StorageError::HashMismatch);
        }
        Ok(PutOutcome::Created {
            etag: header(&response, reqwest::header::ETAG.as_str()),
            version_id: header(&response, "x-amz-version-id"),
        })
    }

    /// `GetObject` of the current version, read whole and bounded: a body
    /// over `max_bytes` fails before it is buffered (a declared
    /// `Content-Length` over the bound fails before the first chunk). Asks
    /// for the stored checksum (`x-amz-checksum-mode: ENABLED`) and, when
    /// the service reports one, verifies the body against it in-module.
    /// The request and the whole body read run under the management
    /// deadline. `Ok(None)` when the key does not exist.
    ///
    /// # Errors
    /// [`StorageError::Validation`] for a body over `max_bytes`;
    /// [`StorageError::HashMismatch`] when the body does not match the
    /// stored checksum; [`StorageError::Timeout`]; request failures
    /// otherwise.
    pub async fn get_object(
        &self,
        path: &StoragePath,
        max_bytes: u64,
    ) -> Result<Option<FetchedObject>, StorageError> {
        let result = self
            .management_request(
                "GET",
                path,
                Vec::new(),
                vec![("x-amz-checksum-mode".to_owned(), "ENABLED".to_owned())],
                Bytes::new(),
            )
            .await;
        let response = match result {
            Ok(response) => response,
            Err(StorageError::S3 { ref code, .. }) if code == "NoSuchKey" || code == "NotFound" => {
                return Ok(None);
            }
            Err(StorageError::Http {
                status_code: 404, ..
            }) => return Ok(None),
            Err(error) => return Err(error),
        };
        if response
            .content_length()
            .is_some_and(|length| length > max_bytes)
        {
            return Err(StorageError::Validation(format!(
                "object {path} exceeds the {max_bytes}-byte read bound"
            )));
        }
        let version = header(&response, "x-amz-version-id");
        let etag = header(&response, reqwest::header::ETAG.as_str());
        let checksum = header(&response, "x-amz-checksum-sha256");
        let read = async {
            let mut stream = response.bytes_stream();
            let mut body: Vec<u8> = Vec::new();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(StorageError::transport)?;
                if exceeds(body.len().saturating_add(chunk.len()), max_bytes) {
                    return Err(StorageError::Validation(format!(
                        "object {path} exceeds the {max_bytes}-byte read bound"
                    )));
                }
                body.extend_from_slice(&chunk);
            }
            Ok(body)
        };
        let body =
            tokio::time::timeout(self.config.management_timeout.max(MIN_DURATION_KNOB), read)
                .await
                .map_err(|_| StorageError::Timeout)??;
        if let Some(reported) = &checksum
            && !checksum_matches(reported, &seaworthy_crypto::digest::sha256(&body))
        {
            return Err(StorageError::HashMismatch);
        }
        Ok(Some(FetchedObject {
            body: Bytes::from(body),
            version_id: version,
            etag,
            checksum_sha256: checksum,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_options_default_to_the_write_once_shape() {
        let options = PutOptions::create_only();
        assert!(options.create_only);
        assert_eq!(options.content_type, super::super::DEFAULT_CONTENT_TYPE);
        assert_eq!(options.max_body_bytes, MAX_DIRECT_OBJECT_BYTES);
        assert!(options.metadata.is_empty() && options.timeout.is_none());
        assert!(options.if_match.is_none());
        let replacing = PutOptions::create_only().with_if_match("\"e1\"");
        assert!(!replacing.create_only);
        assert_eq!(replacing.if_match.as_deref(), Some("\"e1\""));
    }

    #[test]
    fn a_412_is_told_apart_from_other_failures() {
        let s3 = |code: &str| StorageError::S3 {
            code: code.to_owned(),
            message: String::new(),
        };
        let http = |status_code: u16| StorageError::Http {
            status_code,
            error_text: String::new(),
        };
        assert!(is_precondition_failed(&s3("PreconditionFailed")));
        assert!(is_precondition_failed(&http(412)));
        assert!(!is_precondition_failed(&http(409)));
        assert!(is_not_found(&http(404)));
        assert!(is_not_found(&s3("NoSuchKey")));
        assert!(!is_not_found(&http(412)));
    }

    #[test]
    fn the_size_bound_compares_without_overflow() {
        assert!(!exceeds(0, 0));
        assert!(exceeds(1, 0));
        assert!(!exceeds(64, 64));
        assert!(exceeds(65, 64));
        assert!(!exceeds(usize::MAX, u64::MAX));
    }
}
