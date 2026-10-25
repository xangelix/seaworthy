//! The S3 publish client: the management operations a publication needs,
//! over the hand-rolled [`sigv4`] signer and reqwest on the crypto crate's
//! TLS client builder (rustls-no-provider +
//! `seaworthy_crypto::tls::client_config_builder()`: the canonical AWS-LC
//! provider and the TLS policy, plus the platform verifier). No AWS SDK:
//! the SDK drags a second cryptography stack and a second rustls into the
//! tree.
//!
//! - **Write-once puts** ([`S3Backend::put_object`]): create-only on
//!   request (`If-None-Match: *`), an in-module SHA-256
//!   `x-amz-checksum-sha256` on EVERY write, and the stored type, cache
//!   rule and user metadata, all signed.
//! - **Verified reads**: [`S3Backend::head_object_detail`] (size, type,
//!   cache rule, stored SHA-256, user metadata), [`S3Backend::get_object`]
//!   (bounded, checksum-verified), [`S3Backend::get_stream`] (for objects
//!   the caller hashes in flight).
//! - [`S3Backend::list_objects_v2`] (one page under a prefix) and
//!   [`S3Backend::delete_object`] (idempotent).
//! - **Addressing**: path-style for custom endpoints (R2/RustFS),
//!   virtual-hosted for AWS proper; virtual-hosted with a custom endpoint
//!   targets `{bucket}.{endpoint host}`, never `amazonaws.com`.
//!
//! **Security posture.** https-only except loopback (and no userinfo or
//! path in the endpoint); the bucket, region and key prefix are validated
//! at construction (nothing URL-meaningful reaches a URL); every request
//! and every response body read runs under a deadline; response bodies are
//! read bounded (XML pages at [`MAX_XML_BODY_BYTES`], error bodies at
//! 64 KiB, objects at the caller's bound); redirects are never followed
//! (a SigV4 signature is host-bound, and a followed 307 would carry the
//! signed headers, session token included, cross-host); the secret access
//! key and the session token are zeroized on drop and never `Debug`-printed;
//! a request URL never reaches an error message; endpoint-controlled error
//! text is control-character-stripped.
//!
//! Known store quirks pinned by tests: self-hosted endpoints (RustFS)
//! default to path-style addressing; R2 reports `region auto`; a HEAD 404
//! carries no body.

// The client parses network-delivered data: no panicking index or slice,
// no unchecked arithmetic, no `unreachable!` anywhere in it.
#![deny(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unreachable
)]

use std::time::Duration;

use bytes::Bytes;
use futures_util::StreamExt as _;
use zeroize::Zeroizing;

mod direct;
mod error;
pub mod path;
pub mod sigv4;
pub mod xml;

pub use direct::{
    FetchedObject, MAX_DIRECT_OBJECT_BYTES, MAX_PUT_TIMEOUT, MAX_SINGLE_PUT_BYTES,
    MAX_USER_METADATA, ObjectDetail, PutOptions, PutOutcome, USER_METADATA_PREFIX,
};
pub use error::StorageError;
pub use path::StoragePath;

use sigv4::{Payload, SignRequest, Signer};

/// The SigV4 service name.
const SERVICE: &str = "s3";

/// The default stored `Content-Type` when the caller names none: opaque
/// bytes.
pub const DEFAULT_CONTENT_TYPE: &str = "application/octet-stream";

/// The longest header value the client signs (content types, cache rules,
/// metadata values): real values are tens of bytes.
pub const MAX_HEADER_VALUE_BYTES: usize = 255;

/// Default deadline per management call (30 s: these are small
/// request/response exchanges).
pub const DEFAULT_MANAGEMENT_TIMEOUT: Duration = Duration::from_secs(30);

/// Duration knobs floor at 100 ms at the use site: a zero timeout would
/// fail every attempt instantly.
pub(crate) const MIN_DURATION_KNOB: Duration = Duration::from_millis(100);

/// The success-body cap for XML management responses (8 MiB): a
/// `ListObjectsV2` page is ≤1000 keys of ~200 B each; anything larger is
/// a hostile or broken endpoint and must fail, never be parsed truncated
/// (a truncated XML could silently mis-list).
pub const MAX_XML_BODY_BYTES: u64 = 8 * 1024 * 1024;

/// A stream of object bytes ([`S3Backend::get_stream`]).
pub type ObjectStream = futures_util::stream::BoxStream<'static, Result<Bytes, StorageError>>;

/// Validate a header value the client signs into a request: 1..=255
/// printable ASCII bytes (no control characters: a CR/LF would be header
/// injection, and non-ASCII has no portable header encoding).
pub(crate) fn validate_header_value(value: &str, what: &str) -> Result<(), StorageError> {
    if value.is_empty()
        || value.len() > MAX_HEADER_VALUE_BYTES
        || !value.bytes().all(|b| (0x20..=0x7e).contains(&b))
    {
        return Err(StorageError::Validation(format!(
            "{what} must be 1..={MAX_HEADER_VALUE_BYTES} printable ASCII bytes"
        )));
    }
    Ok(())
}

/// Validate a media type the client stores for an object: a header-safe
/// `type/subtype[; params]`.
pub(crate) fn validate_content_type(value: &str) -> Result<(), StorageError> {
    validate_header_value(value, "content type")?;
    let essence = value.split(';').next().unwrap_or_default().trim();
    let token = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$&-^_.+".contains(&b))
    };
    match essence.split_once('/') {
        Some((kind, subtype)) if token(kind) && token(subtype) => Ok(()),
        _ => Err(StorageError::Validation(format!(
            "content type {value:?} is not a type/subtype media type"
        ))),
    }
}

/// One entry from a [`S3Backend::list_objects_v2`] page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListedObject {
    /// The object path (relative to the backend's key prefix).
    pub path: String,
    /// The size in bytes.
    pub size: u64,
    /// The ETag (verbatim, quotes preserved), when the store sent one.
    pub etag: Option<String>,
    /// The store-reported modification time (ISO 8601), when it sent one.
    pub last_modified: Option<String>,
}

/// A page from [`S3Backend::list_objects_v2`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ListPage {
    /// The page's objects.
    pub objects: Vec<ListedObject>,
    /// The continuation token for the next page (`None` = last page).
    pub continuation: Option<String>,
}

/// S3 backend configuration.
#[derive(Clone)]
pub struct S3Config {
    /// The bucket name.
    pub bucket: String,
    /// The region (`"auto"` for R2).
    pub region: String,
    /// The custom endpoint (`https://…`; `http://` only for loopback, e.g.
    /// a RustFS dev server or a test stub). `None` = AWS proper.
    pub endpoint: Option<String>,
    /// The static credentials.
    pub credentials: sigv4::Credentials,
    /// An optional key prefix (all paths are resolved under it).
    pub key_prefix: Option<String>,
    /// Addressing override; default: path-style for custom endpoints,
    /// virtual-hosted for AWS.
    pub path_style: Option<bool>,
    /// Total deadline per management call (`HeadObject`, `GetObject`
    /// including its bounded body read, `DeleteObject`, `ListObjectsV2`, a
    /// `PutObject` without its own deadline, the head of a
    /// [`S3Backend::get_stream`]). Floored at 100 ms at the use site.
    pub management_timeout: Duration,
}

impl S3Config {
    /// A minimal config: bucket, region, credentials. Defaults: AWS
    /// endpoint (virtual-hosted), the 30 s management deadline.
    #[must_use]
    pub fn new(
        bucket: impl Into<String>,
        region: impl Into<String>,
        access_key_id: impl Into<String>,
        secret_access_key: impl Into<String>,
    ) -> Self {
        Self {
            bucket: bucket.into(),
            region: region.into(),
            endpoint: None,
            credentials: sigv4::Credentials {
                access_key_id: access_key_id.into(),
                secret_access_key: Zeroizing::new(secret_access_key.into()),
                session_token: None,
            },
            key_prefix: None,
            path_style: None,
            management_timeout: DEFAULT_MANAGEMENT_TIMEOUT,
        }
    }

    /// Set a custom endpoint (R2/RustFS/loopback stub).
    #[must_use]
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = Some(endpoint.into());
        self
    }

    /// Set an STS session token (signed as `x-amz-security-token`; zeroized
    /// on drop, never `Debug`-printed).
    #[must_use]
    pub fn with_session_token(mut self, token: impl Into<String>) -> Self {
        self.credentials.session_token = Some(Zeroizing::new(token.into()));
        self
    }

    /// Set a key prefix. A leading `/` is normalized away (the prefix is a
    /// KEY fragment, not a path: `/uploads` would otherwise address
    /// `/{bucket}//uploads/{key}`, a `//` no real layout has); the trailing
    /// trim in `key`/`unkey` stays.
    #[must_use]
    pub fn with_key_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.key_prefix = Some(prefix.into().trim_start_matches('/').to_owned());
        self
    }

    /// Force path-style addressing on/off. Virtual-hosted style with a
    /// custom endpoint addresses `{bucket}.{endpoint host}` (the bucket
    /// must then satisfy the strict S3/DNS grammar; an IP-literal endpoint
    /// cannot host buckets and is refused).
    #[must_use]
    pub const fn with_path_style(mut self, path_style: bool) -> Self {
        self.path_style = Some(path_style);
        self
    }

    /// Set the per-call management deadline (default
    /// [`DEFAULT_MANAGEMENT_TIMEOUT`]). A black-holing endpoint (accepts,
    /// never responds) must never park a call forever.
    #[must_use]
    pub const fn with_management_timeout(mut self, timeout: Duration) -> Self {
        self.management_timeout = timeout;
        self
    }
}

impl std::fmt::Debug for S3Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Config")
            .field("bucket", &self.bucket)
            .field("region", &self.region)
            .field("endpoint", &self.endpoint)
            .field("credentials", &self.credentials)
            .field("key_prefix", &self.key_prefix)
            .field("path_style", &self.path_style)
            .field("management_timeout", &self.management_timeout)
            .finish()
    }
}

/// The resolved addressing for one request: host + raw (unencoded) path.
#[derive(Clone)]
struct Address {
    host: String,
    /// The raw path for signing (e.g. `/bucket/key` path-style).
    raw_path: String,
    /// The scheme+authority base for URL assembly.
    base_url: String,
    /// The encoded object path (for URL assembly).
    encoded_path: String,
}

/// The S3/R2/RustFS backend.
pub struct S3Backend {
    config: S3Config,
    client: reqwest::Client,
    signer: Signer,
    path_style: bool,
    /// `https`/`http` (the endpoint's scheme; `https` for AWS).
    scheme: String,
    /// The authority every request targets: the endpoint's `host[:port]`
    /// (path-style), `{bucket}.{endpoint host}[:port]` (virtual-hosted
    /// custom endpoint), or `{bucket}.s3.{region}.amazonaws.com`.
    authority: String,
}

impl std::fmt::Debug for S3Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Backend")
            .field("config", &self.config)
            .field("scheme", &self.scheme)
            .field("authority", &self.authority)
            .field("path_style", &self.path_style)
            .finish_non_exhaustive()
    }
}

impl S3Backend {
    /// Build a backend on the client's own hardened HTTPS client (the
    /// crypto crate's TLS configuration, no redirects, connect and read
    /// timeouts).
    ///
    /// # Errors
    /// [`StorageError::Validation`] / [`StorageError::Http`] on invalid
    /// configuration (plaintext non-loopback endpoint, bad URL, a bucket,
    /// region or prefix outside its grammar, TLS construction failure);
    /// [`StorageError::Crypto`] for a secret below the HMAC key floor under
    /// `fips`.
    pub fn new(config: S3Config) -> Result<Self, StorageError> {
        Self::validate(&config)?;
        let path_style = config
            .path_style
            .unwrap_or_else(|| config.endpoint.is_some());
        let (scheme, authority) = match &config.endpoint {
            Some(endpoint) => {
                let url = reqwest::Url::parse(endpoint).map_err(|e| StorageError::Http {
                    status_code: 0,
                    error_text: format!("invalid endpoint url: {e}"),
                })?;
                let host = url.host_str().unwrap_or_default();
                let host = match url.port() {
                    Some(port) => format!("{host}:{port}"),
                    None => host.to_owned(),
                };
                let authority = if path_style {
                    host
                } else {
                    format!("{}.{host}", config.bucket)
                };
                (url.scheme().to_owned(), authority)
            }
            None if path_style => (
                "https".to_owned(),
                format!("s3.{}.amazonaws.com", config.region),
            ),
            None => (
                "https".to_owned(),
                format!("{}.s3.{}.amazonaws.com", config.bucket, config.region),
            ),
        };
        // The HMAC key floor at intake: the SigV4 chain's first HMAC key is
        // `AWS4` + the secret access key, refused here (a typed
        // construction error) when the facade would refuse it at the first
        // request.
        seaworthy_crypto::hmac::ensure_key_strength(
            Zeroizing::new(format!(
                "AWS4{}",
                config.credentials.secret_access_key.as_str()
            ))
            .as_bytes(),
        )?;
        let signer = Signer::new(
            config.credentials.clone(),
            config.region.clone(),
            SERVICE.to_owned(),
        );
        Ok(Self {
            client: default_client()?,
            config,
            signer,
            path_style,
            scheme,
            authority,
        })
    }

    /// https-only except loopback (signed requests carry credentials-derived
    /// headers and the session token; they must never cross plaintext links
    /// off-loopback), and every name that reaches a URL in its grammar.
    fn validate(config: &S3Config) -> Result<(), StorageError> {
        if let Some(endpoint) = &config.endpoint {
            let url = reqwest::Url::parse(endpoint).map_err(|e| StorageError::Http {
                status_code: 0,
                error_text: format!("invalid endpoint url: {e}"),
            })?;
            // A path component can never sign correctly: the signer
            // addresses `/{bucket}/{key}`, so the endpoint's own prefix
            // would be absent from the canonical request and every call
            // would 403. Fail at construction, not at the first request.
            if !url.path().is_empty() && url.path() != "/" {
                return Err(StorageError::Validation(
                    "endpoint carries a path component the signer cannot honor; \
                     use the bare origin"
                        .to_owned(),
                ));
            }
            // Credentials do not belong in a URL. Never echoed.
            if !url.username().is_empty() || url.password().is_some() {
                return Err(StorageError::Validation(
                    "endpoint carries userinfo — credentials in the URL are refused".to_owned(),
                ));
            }
            match url.scheme() {
                "https" => {}
                "http" if is_loopback_host(url.host_str().unwrap_or_default()) => {}
                scheme => {
                    return Err(StorageError::Http {
                        status_code: 0,
                        error_text: format!(
                            "endpoint scheme {scheme:?} refused: https-only except loopback"
                        ),
                    });
                }
            }
        }
        // Bucket naming. The strict S3 grammar applies to AWS's own
        // endpoints AND to every virtual-hosted address (the bucket becomes
        // a DNS label there). Custom path-style endpoints (R2/RustFS accept
        // wider names: upper case, underscores) get `[A-Za-z0-9._-]` only:
        // nothing URL-meaningful (`@` would move the authority, `#`/`?`
        // would cut the path) can reach a URL.
        let bucket = &config.bucket;
        let path_style = config
            .path_style
            .unwrap_or_else(|| config.endpoint.is_some());
        let strict_grammar = || {
            let bytes = bucket.as_bytes();
            (3..=63).contains(&bytes.len())
                && bytes.iter().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'.' || *b == b'-'
                })
                && !bucket.starts_with(['.', '-'])
                && !bucket.ends_with(['.', '-'])
                && !bucket.contains("..")
                && bucket.parse::<std::net::Ipv4Addr>().is_err()
        };
        if config.endpoint.is_none() || !path_style {
            if !strict_grammar() {
                return Err(StorageError::Validation(format!(
                    "bucket {bucket:?} violates the S3 naming grammar (3-63 chars of [a-z0-9.-], \
                     no leading/trailing '.' or '-', no '..', not IP-shaped) — required for AWS \
                     endpoints and virtual-hosted addressing"
                )));
            }
        } else {
            let floor = (1..=255).contains(&bucket.len())
                && bucket
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
            if !floor {
                return Err(StorageError::Validation(format!(
                    "bucket {:?} is unusable (a custom endpoint requires 1-255 chars of \
                     [A-Za-z0-9._-])",
                    error::line_safe(bucket)
                )));
            }
        }
        // Virtual-hosted with a custom endpoint: `{bucket}.{host}` needs a
        // DNS-name host; an IP literal cannot carry a bucket label.
        if !path_style
            && let Some(endpoint) = &config.endpoint
            && let Ok(url) = reqwest::Url::parse(endpoint)
            && url
                .host_str()
                .unwrap_or_default()
                .trim_matches(|c| c == '[' || c == ']')
                .parse::<std::net::IpAddr>()
                .is_ok()
        {
            return Err(StorageError::Validation(
                "virtual-hosted addressing needs a DNS-name endpoint (an IP literal cannot host \
                 `{bucket}.` labels) — use path style"
                    .to_owned(),
            ));
        }
        // Region: it lands in the credential scope and (AWS) the host.
        let region = &config.region;
        if !(1..=32).contains(&region.len())
            || !region
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(StorageError::Validation(format!(
                "region {:?} must be 1-32 chars of [a-z0-9-]",
                error::line_safe(region)
            )));
        }
        // Key prefix: a key fragment with StoragePath's own rules (no
        // `..`/`.`/empty segments: a `..` would be URL-normalized away AFTER
        // signing, failing every request confusingly).
        if let Some(prefix) = &config.key_prefix {
            let trimmed = prefix.trim_matches('/');
            if !trimmed.is_empty() {
                StoragePath::new(trimmed).map_err(|e| {
                    StorageError::Validation(format!("key prefix is not a valid key fragment: {e}"))
                })?;
            }
        }
        Ok(())
    }

    /// The underlying reqwest client (the same hardened client: for a
    /// caller's own fetches, such as reading a publication back through its
    /// public URL).
    #[must_use]
    pub fn http_client(&self) -> &reqwest::Client {
        &self.client
    }

    /// The configured bucket.
    #[must_use]
    pub fn bucket(&self) -> &str {
        &self.config.bucket
    }

    /// The full object key (prefix applied).
    fn key(&self, path: &StoragePath) -> String {
        match &self.config.key_prefix {
            Some(prefix) => format!("{}/{}", prefix.trim_end_matches('/'), path.as_str()),
            None => path.as_str().to_owned(),
        }
    }

    /// Strip the configured prefix back off a full key (for `list`).
    fn unkey(&self, key: &str) -> String {
        match &self.config.key_prefix {
            Some(prefix) => {
                let prefix = format!("{}/", prefix.trim_end_matches('/'));
                key.strip_prefix(&prefix).unwrap_or(key).to_owned()
            }
            None => key.to_owned(),
        }
    }

    /// Resolve addressing for `path`.
    fn address(&self, path: &StoragePath) -> Address {
        let key = self.key(path);
        let raw_path = if self.path_style {
            format!("/{}/{key}", self.config.bucket)
        } else {
            format!("/{key}")
        };
        Address {
            host: self.authority.clone(),
            encoded_path: sigv4::uri_encode(&raw_path, true),
            raw_path,
            base_url: format!("{}://{}", self.scheme, self.authority),
        }
    }

    /// The bucket-root address for `ListObjectsV2` (no key component).
    fn list_address(&self) -> Address {
        let raw_path = if self.path_style {
            format!("/{}", self.config.bucket)
        } else {
            "/".to_owned()
        };
        Address {
            host: self.authority.clone(),
            encoded_path: sigv4::uri_encode(&raw_path, true),
            raw_path,
            base_url: format!("{}://{}", self.scheme, self.authority),
        }
    }

    /// Header-signed management request. Returns the raw response; errors
    /// (non-2xx) are classified into [`StorageError::S3`]/[`StorageError::Http`].
    async fn management_request(
        &self,
        method: &str,
        path: &StoragePath,
        query: Vec<(String, String)>,
        extra_headers: Vec<(String, String)>,
        body: Bytes,
    ) -> Result<reqwest::Response, StorageError> {
        self.signed_request(method, &self.address(path), query, extra_headers, body)
            .await
    }

    /// [`management_request`](Self::management_request) under `deadline`
    /// instead of the management one: a large direct body takes longer
    /// to send than any management call should.
    async fn management_request_within(
        &self,
        method: &str,
        path: &StoragePath,
        extra_headers: Vec<(String, String)>,
        body: Bytes,
        deadline: Duration,
    ) -> Result<reqwest::Response, StorageError> {
        self.signed_request_within(
            method,
            &self.address(path),
            Vec::new(),
            extra_headers,
            body,
            deadline,
        )
        .await
    }

    /// One header-signed request against `address`, the send (and, on the
    /// error path, the bounded error-body read) under ONE management
    /// deadline, `ListObjectsV2` included.
    async fn signed_request(
        &self,
        method: &str,
        address: &Address,
        query: Vec<(String, String)>,
        extra_headers: Vec<(String, String)>,
        body: Bytes,
    ) -> Result<reqwest::Response, StorageError> {
        self.signed_request_within(
            method,
            address,
            query,
            extra_headers,
            body,
            self.config.management_timeout,
        )
        .await
    }

    /// [`signed_request`](Self::signed_request) under `deadline`.
    async fn signed_request_within(
        &self,
        method: &str,
        address: &Address,
        query: Vec<(String, String)>,
        extra_headers: Vec<(String, String)>,
        body: Bytes,
        deadline: Duration,
    ) -> Result<reqwest::Response, StorageError> {
        let method = match method {
            "GET" => reqwest::Method::GET,
            "PUT" => reqwest::Method::PUT,
            "POST" => reqwest::Method::POST,
            "DELETE" => reqwest::Method::DELETE,
            "HEAD" => reqwest::Method::HEAD,
            other => {
                return Err(StorageError::Http {
                    status_code: 0,
                    error_text: format!("unsupported method {other}"),
                });
            }
        };
        let payload_hash = seaworthy_crypto::digest::sha256_hex(&body);
        let amz_datetime = sigv4::current_amz_datetime();
        let request = SignRequest {
            method: method.as_str(),
            host: &address.host,
            path: &address.raw_path,
            query: query.clone(),
            headers: extra_headers.clone(),
            payload: Payload::Sha256Hex(&payload_hash),
            normalize_path: false,
            content_sha256_header: true,
            amz_datetime: &amz_datetime,
        };
        let signed = self.signer.signed_headers(&request)?;
        let url = assemble_url(address, &sigv4::canonical_query(&query));

        let mut builder = self.client.request(method, &url).body(body);
        // Signed extra headers (the type, checksum, condition, metadata)
        // must ride the wire too: the signature commits to them.
        for (name, value) in &extra_headers {
            builder = builder.header(name.clone(), value.clone());
        }
        for (name, value) in signed {
            builder = builder.header(name, value);
        }
        // One deadline covers the whole exchange: the send, and (on the
        // error path) the bounded error-body read inside the classifier.
        let work = async {
            let response = builder.send().await.map_err(StorageError::transport)?;
            if !response.status().is_success() {
                return Err(error::error_from_response(response).await);
            }
            Ok(response)
        };
        tokio::time::timeout(deadline.max(MIN_DURATION_KNOB), work)
            .await
            .map_err(|_| StorageError::Timeout)?
    }

    /// `HeadObject` with the stored checksum asked for
    /// (`x-amz-checksum-mode: ENABLED`): the size, ETag and modification
    /// time, and what a publisher checks on its objects: the stored
    /// `Content-Type`, `Cache-Control`, user metadata and full-object
    /// SHA-256 (base64, as S3 reports it; `None` when the service has none,
    /// or a multipart object's composite one, which carries a `-<parts>`
    /// suffix). `Ok(None)` on 404.
    ///
    /// # Errors
    /// On non-404 failures; a response without `Content-Length`.
    pub async fn head_object_detail(
        &self,
        path: &StoragePath,
    ) -> Result<Option<ObjectDetail>, StorageError> {
        let result = self
            .management_request(
                "HEAD",
                path,
                Vec::new(),
                vec![("x-amz-checksum-mode".to_owned(), "ENABLED".to_owned())],
                Bytes::new(),
            )
            .await;
        match result {
            Ok(response) => {
                let text = |name: &str| {
                    response
                        .headers()
                        .get(name)
                        .and_then(|h| h.to_str().ok())
                        .map(str::to_owned)
                };
                let size = text(reqwest::header::CONTENT_LENGTH.as_str())
                    .and_then(|s| s.parse::<u64>().ok())
                    .ok_or_else(|| StorageError::Http {
                        status_code: 0,
                        error_text: "HEAD response missing Content-Length".to_owned(),
                    })?;
                let metadata = response
                    .headers()
                    .iter()
                    .filter_map(|(name, value)| {
                        let key = name.as_str().strip_prefix(USER_METADATA_PREFIX)?;
                        Some((key.to_owned(), value.to_str().ok()?.to_owned()))
                    })
                    .collect();
                Ok(Some(ObjectDetail {
                    size,
                    metadata,
                    etag: text(reqwest::header::ETAG.as_str()),
                    last_modified: text(reqwest::header::LAST_MODIFIED.as_str()),
                    content_type: text(reqwest::header::CONTENT_TYPE.as_str()),
                    cache_control: text(reqwest::header::CACHE_CONTROL.as_str()),
                    sha256: text("x-amz-checksum-sha256").filter(|c| !c.contains('-')),
                }))
            }
            // HEAD errors carry no body, so a 404 surfaces as plain Http;
            // the S3 shape is belt-and-braces for services that do send one.
            Err(StorageError::Http {
                status_code: 404, ..
            }) => Ok(None),
            Err(StorageError::S3 { ref code, .. }) if code == "NoSuchKey" || code == "NotFound" => {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// `GetObject` as a stream, header-signed (for an object the caller
    /// hashes in flight). The deadline bounds the request and the response
    /// head; the body stream is deliberately unbounded in time (objects can
    /// be large: stall detection there is the client's per-read timeout)
    /// and in size (the CALLER bounds what it reads).
    ///
    /// # Errors
    /// Request failures (a missing key is [`StorageError::S3`] `NoSuchKey`
    /// or [`StorageError::Http`] 404); [`StorageError::Timeout`].
    pub async fn get_stream(&self, path: &StoragePath) -> Result<ObjectStream, StorageError> {
        let response = self
            .management_request("GET", path, Vec::new(), Vec::new(), Bytes::new())
            .await?;
        Ok(Box::pin(
            response
                .bytes_stream()
                .map(|chunk| chunk.map_err(StorageError::transport)),
        ))
    }

    /// `DeleteObject`: idempotent (S3 answers 204 for missing keys too).
    ///
    /// # Errors
    /// On genuine failures.
    pub async fn delete_object(&self, path: &StoragePath) -> Result<(), StorageError> {
        self.management_request("DELETE", path, Vec::new(), Vec::new(), Bytes::new())
            .await?;
        Ok(())
    }

    /// One `ListObjectsV2` page of every key under `prefix/` (relative to
    /// the backend's key prefix; paths come back relative to it too). A
    /// page that says it is truncated but names no continuation token is
    /// an error, never a short listing read as complete.
    ///
    /// # Errors
    /// On request/parse failure; [`StorageError::Xml`] for a truncated page
    /// without a continuation token.
    pub async fn list_objects_v2(
        &self,
        prefix: &StoragePath,
        max_keys: Option<u32>,
        continuation: Option<&str>,
    ) -> Result<ListPage, StorageError> {
        let mut query = vec![
            ("list-type".to_owned(), "2".to_owned()),
            ("prefix".to_owned(), self.key(prefix) + "/"),
        ];
        if let Some(max_keys) = max_keys {
            query.push(("max-keys".to_owned(), max_keys.to_string()));
        }
        if let Some(token) = continuation {
            query.push(("continuation-token".to_owned(), token.to_owned()));
        }
        // The list request targets the bucket root, not an object path,
        // and runs under the management deadline like every other call.
        let response = self
            .signed_request("GET", &self.list_address(), query, Vec::new(), Bytes::new())
            .await?;
        let text = self.read_xml_body(response).await?;
        let parsed = xml::parse_list_objects_v2(&text)?;
        // The token only means something on a truncated page; a truncated
        // page without one has no way to continue: a broken endpoint must
        // fail, never read as a complete listing.
        let continuation = parsed
            .next_continuation_token
            .filter(|token| parsed.is_truncated && !token.is_empty());
        if parsed.is_truncated && continuation.is_none() {
            return Err(StorageError::Xml(
                "a truncated ListObjectsV2 page without a NextContinuationToken".to_owned(),
            ));
        }
        Ok(ListPage {
            objects: parsed
                .objects
                .into_iter()
                .map(|o| ListedObject {
                    path: self.unkey(&o.key),
                    size: o.size,
                    etag: o.etag,
                    last_modified: o.last_modified,
                })
                .collect(),
            continuation,
        })
    }

    /// Read a management success body: bounded at [`MAX_XML_BODY_BYTES`]
    /// BEFORE parsing, under the management deadline (a stalled body is
    /// the black-hole case the timeout exists for).
    async fn read_xml_body(&self, response: reqwest::Response) -> Result<String, StorageError> {
        let read = async {
            let mut stream = response.bytes_stream();
            let mut body: Vec<u8> = Vec::new();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(StorageError::transport)?;
                let within = u64::try_from(body.len().saturating_add(chunk.len()))
                    .is_ok_and(|len| len <= MAX_XML_BODY_BYTES);
                if !within {
                    return Err(StorageError::Http {
                        status_code: 0,
                        error_text: format!(
                            "response body exceeds the {} MiB management cap",
                            MAX_XML_BODY_BYTES / (1024 * 1024),
                        ),
                    });
                }
                body.extend_from_slice(&chunk);
            }
            Ok(String::from_utf8_lossy(&body).into_owned())
        };
        tokio::time::timeout(self.config.management_timeout.max(MIN_DURATION_KNOB), read)
            .await
            .map_err(|_| StorageError::Timeout)?
    }
}

/// Loopback hosts exempt from the https-only rule.
fn is_loopback_host(host: &str) -> bool {
    let host = host.trim_matches(|c| c == '[' || c == ']');
    host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// The client's reqwest client: the crypto crate's TLS client builder
/// (`seaworthy_crypto::tls::client_config_builder()`: the canonical
/// provider, FIPS-restricted under `seaworthy-crypto/fips`, the policy's
/// versions and groups) with the operating system's trust store (the
/// platform verifier) and no client certificate, preconfigured: never
/// whatever process default happens to be set. Timeouts of 10 s to connect
/// and 30 s per-read stall. NO total request timeout here:
/// every call carries its own deadline (`S3Config::management_timeout`,
/// `PutOptions::timeout`). Redirects are NEVER followed: a 307/308 would
/// re-send the body and carry the `x-amz-*` headers (the STS session token
/// included) cross-host, and a SigV4 signature is host-bound, so a
/// followed redirect could never validate anyway.
fn default_client() -> Result<reqwest::Client, StorageError> {
    use rustls_platform_verifier::BuilderVerifierExt as _;
    let tls = seaworthy_crypto::tls::client_config_builder()
        .and_then(|builder| builder.with_platform_verifier())
        // A TLS stack that cannot initialize (the platform verifier: no
        // trust store) is a typed error, never a panic.
        .map_err(|e| StorageError::Http {
            status_code: 0,
            error_text: format!("tls client configuration: {e}"),
        })?
        .with_no_client_auth();
    reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .read_timeout(Duration::from_secs(30))
        .build()
        .map_err(StorageError::transport)
}

/// Assemble the full URL for an address + optional query string.
fn assemble_url(address: &Address, query: &str) -> String {
    if query.is_empty() {
        format!("{}{}", address.base_url, address.encoded_path)
    } else {
        format!("{}{}?{query}", address.base_url, address.encoded_path)
    }
}

/// Base64 (standard, padded): the `x-amz-checksum-*` wire encoding.
fn b64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Whether a service-reported `x-amz-checksum-sha256` proves `expected`:
/// the full-object form (`b64(sha256)`) or S3's one-part COMPOSITE form
/// (`b64(sha256(part digest))-1`); both derive from the object's bytes
/// alone for a single-part upload.
fn checksum_matches(reported: &str, expected: &[u8; 32]) -> bool {
    let full = b64(expected);
    let composite = format!("{}-1", b64(&seaworthy_crypto::digest::sha256(expected)));
    seaworthy_crypto::ct_eq(reported.as_bytes(), full.as_bytes())
        || seaworthy_crypto::ct_eq(reported.as_bytes(), composite.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_hosts_are_exactly_the_loopback_addresses() {
        for host in ["localhost", "127.0.0.1", "127.8.9.10", "::1", "[::1]"] {
            assert!(is_loopback_host(host), "{host}");
        }
        for host in [
            "example.com",
            "localhost.example.com",
            "10.0.0.1",
            "0.0.0.0",
            "::",
            "[::ffff:10.0.0.1]",
            "",
        ] {
            assert!(!is_loopback_host(host), "{host}");
        }
    }

    #[test]
    fn content_types_are_header_safe_media_types() {
        for good in [
            "application/octet-stream",
            "application/vnd.debian.binary-package",
            "text/plain; charset=utf-8",
            "application/x-rpm",
        ] {
            validate_content_type(good).unwrap_or_else(|e| panic!("{good}: {e}"));
        }
        for bad in [
            "",
            "text",
            "/plain",
            "text/",
            "text/plain\r\nx-evil: 1",
            "text/pla in",
            "téxt/plain",
        ] {
            assert!(validate_content_type(bad).is_err(), "{bad:?}");
        }
        assert!(validate_header_value(&"a".repeat(MAX_HEADER_VALUE_BYTES), "v").is_ok());
        assert!(validate_header_value(&"a".repeat(MAX_HEADER_VALUE_BYTES + 1), "v").is_err());
    }

    #[test]
    fn checksums_match_the_full_and_the_one_part_composite_form() {
        let digest = seaworthy_crypto::digest::sha256(b"object");
        assert!(checksum_matches(&b64(&digest), &digest));
        let composite = format!("{}-1", b64(&seaworthy_crypto::digest::sha256(&digest)));
        assert!(checksum_matches(&composite, &digest));
        assert!(!checksum_matches(
            &b64(&seaworthy_crypto::digest::sha256(b"other")),
            &digest
        ));
        assert!(!checksum_matches(&format!("{composite}x"), &digest));
        assert!(!checksum_matches("", &digest));
    }

    #[test]
    fn debug_output_never_carries_credentials() {
        let config = S3Config::new(
            "bucket",
            "auto",
            "AKIDEXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        )
        .with_session_token("FwoGZXIvYXdzEXAMPLESESSION")
        .with_endpoint("http://127.0.0.1:9000");
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("wJalrXUtnFEMI"), "{rendered}");
        assert!(!rendered.contains("EXAMPLESESSION"), "{rendered}");
        let backend = S3Backend::new(config).expect("backend");
        let rendered = format!("{backend:?}");
        assert!(!rendered.contains("wJalrXUtnFEMI"), "{rendered}");
        assert!(!rendered.contains("EXAMPLESESSION"), "{rendered}");
        assert!(rendered.contains("127.0.0.1:9000"), "{rendered}");
    }

    #[test]
    fn keys_carry_the_prefix_and_listings_strip_it() {
        let backend = S3Backend::new(
            S3Config::new("bucket", "auto", "AKIDEXAMPLE", "a-secret-of-floor-length")
                .with_endpoint("http://127.0.0.1:9000")
                .with_key_prefix("/packages/"),
        )
        .expect("backend");
        let path = StoragePath::new("apt/InRelease").expect("path");
        assert_eq!(backend.key(&path), "packages/apt/InRelease");
        assert_eq!(backend.unkey("packages/apt/InRelease"), "apt/InRelease");
        assert_eq!(backend.unkey("elsewhere/x"), "elsewhere/x");
        let address = backend.address(&path);
        assert_eq!(address.raw_path, "/bucket/packages/apt/InRelease");
        assert_eq!(
            assemble_url(&address, "a=b"),
            "http://127.0.0.1:9000/bucket/packages/apt/InRelease?a=b"
        );
        assert_eq!(backend.list_address().raw_path, "/bucket");
        assert_eq!(backend.bucket(), "bucket");
    }
}
