//! AWS Signature Version 4, hand-rolled over `seaworthy-crypto`
//! (HMAC-SHA-256 + SHA-256: signing lands in the AWS-LC FIPS module when
//! `seaworthy-crypto/fips` is on).
//!
//! **Header signing** ([`Signer::signed_headers`]) for every call the
//! client makes (put, get, head, delete, list): the `Authorization` header
//! carries the signature and the payload hash is the real SHA-256 of the
//! body. Query presigning (credentials in the URL) is deliberately not
//! offered: the publisher never hands a URL to anyone else.
//!
//! The implementation is KAT-driven: the published AWS SigV4 test suite
//! (vendored at `tests/vectors/sigv4/`, Apache-2.0, from the botocore
//! mirror of the awslabs suite) validates canonical requests,
//! strings-to-sign, and final signatures byte-for-byte.
//!
//! Path handling: the suite's `normalize-path` cases require RFC 3986
//! dot-segment removal + slash collapsing, which is correct for generic
//! AWS services but **wrong for S3** (a key may legitimately contain `//`
//! or `/./`). S3 requests therefore sign with `normalize_path: false`; the
//! normalized form exists only to satisfy the generic suite.

use std::time::{SystemTime, UNIX_EPOCH};

use seaworthy_crypto::digest;
use seaworthy_crypto::hmac::hmac_sha256;
use zeroize::Zeroizing;

use super::StorageError;

/// The literal payload-hash value of a request whose body is not hashed
/// (`x-amz-content-sha256: UNSIGNED-PAYLOAD`).
pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";

/// Signing credentials. The secret and the session token are held in
/// zeroizing wrappers, and `Debug` prints neither.
#[derive(Clone)]
pub struct Credentials {
    /// The access key id.
    pub access_key_id: String,
    /// The secret access key (zeroized on drop).
    pub secret_access_key: Zeroizing<String>,
    /// An optional session token (STS; zeroized on drop), signed as
    /// `x-amz-security-token`.
    pub session_token: Option<Zeroizing<String>>,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("access_key_id", &self.access_key_id)
            .field("session_token", &self.session_token.is_some())
            .finish_non_exhaustive()
    }
}

/// A SigV4 signer fixed to a region and service (`s3` everywhere in this
/// client, but the KAT suite signs service `service`).
///
/// The derived signing key (`kSigning`: four chained HMACs over the scope
/// DATE, region, and service) is constant per UTC day, so it is cached per
/// scope date. Clones share the cache (same credentials); the cached key is
/// zeroized on replacement and drop.
#[derive(Clone)]
pub struct Signer {
    credentials: Credentials,
    region: String,
    service: String,
    key_cache: std::sync::Arc<std::sync::Mutex<Option<CachedKey>>>,
}

/// A derived signing key and the scope date it is valid for.
type CachedKey = (String, Zeroizing<[u8; 32]>);

impl std::fmt::Debug for Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signer")
            .field("credentials", &self.credentials)
            .field("region", &self.region)
            .field("service", &self.service)
            .finish_non_exhaustive()
    }
}

/// The payload commitment for a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Payload<'a> {
    /// The lowercase-hex SHA-256 of the exact request body.
    Sha256Hex(&'a str),
    /// `UNSIGNED-PAYLOAD`.
    Unsigned,
}

/// One request to sign. `host` goes in the dedicated field (the signer
/// canonicalizes it); `headers` carries the rest WITHOUT `host`,
/// `authorization`, `x-amz-date`, `x-amz-content-sha256`, or
/// `x-amz-security-token`: the signer adds those.
#[derive(Clone)]
pub struct SignRequest<'a> {
    /// The HTTP method (`GET`, `PUT`, `POST`, `DELETE`, `HEAD`).
    pub method: &'a str,
    /// The authority (`example.amazonaws.com`, or `host:port` for custom
    /// endpoints on non-default ports).
    pub host: &'a str,
    /// The raw (not yet percent-encoded) path, e.g. `/bucket/key`.
    pub path: &'a str,
    /// Query parameters, unencoded, duplicates preserved.
    pub query: Vec<(String, String)>,
    /// Extra headers to sign (e.g. `content-type`, `if-none-match`, the
    /// checksum and the user metadata of a put).
    pub headers: Vec<(String, String)>,
    /// The payload commitment.
    pub payload: Payload<'a>,
    /// RFC 3986 dot-segment normalization + slash collapsing. `false` for
    /// S3 (keys can contain `//`); `true` only to satisfy the generic KAT
    /// suite.
    pub normalize_path: bool,
    /// Add and sign the `x-amz-content-sha256` header (S3 requires it;
    /// generic services, and the KAT suite, sign without it).
    pub content_sha256_header: bool,
    /// The signing timestamp, `YYYYMMDDTHHMMSSZ` (UTC).
    pub amz_datetime: &'a str,
}

/// The fully canonicalized request: the intermediate values the KAT
/// harness asserts on byte-for-byte.
#[derive(Clone, Debug)]
pub struct CanonicalRequest {
    /// The canonical URI (encoded, normalized per the request's flag).
    pub uri: String,
    /// The canonical query string.
    pub query: String,
    /// The canonical headers block (trailing newline included).
    pub headers: String,
    /// The signed-headers list (`;`-joined).
    pub signed_headers: String,
    /// The payload hash line.
    pub payload_hash: String,
    /// The full canonical request text.
    pub text: String,
}

/// RFC 3986 unreserved characters are never percent-encoded.
const fn is_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~')
}

/// Percent-encode `input` per SigV4 (uppercase hex). `keep_slash` preserves
/// `/` (path encoding); query keys/values encode it.
#[must_use]
pub fn uri_encode(input: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(input.len());
    for &byte in input.as_bytes() {
        if is_unreserved(byte) || (keep_slash && byte == b'/') {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push_str(&hex::encode_upper([byte]));
        }
    }
    out
}

/// RFC 3986 §5.2.4 dot-segment removal with AWS's slash collapsing (the
/// generic-service rule the KAT suite pins; never used for S3).
fn normalize_path(path: &str) -> String {
    let mut segments: Vec<&str> = Vec::new();
    for segment in path.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            s => segments.push(s),
        }
    }
    let mut joined = format!("/{}", segments.join("/"));
    if path.ends_with('/') && joined != "/" {
        joined.push('/');
    }
    joined
}

/// The canonical URI: encoded, normalized when the request asks for it.
fn canonical_uri(path: &str, normalize: bool) -> String {
    let path = if normalize {
        normalize_path(path)
    } else {
        path.to_owned()
    };
    let encoded = uri_encode(if path.is_empty() { "/" } else { &path }, true);
    if encoded.is_empty() {
        "/".to_owned()
    } else {
        encoded
    }
}

/// The canonical query string: each key/value percent-encoded, pairs sorted
/// by (encoded key, encoded value), `&`-joined. Duplicates survive (the
/// suite's `get-vanilla-query-order-*` cases).
#[must_use]
pub fn canonical_query(query: &[(String, String)]) -> String {
    let mut pairs: Vec<(String, String)> = query
        .iter()
        .map(|(k, v)| (uri_encode(k, false), uri_encode(v, false)))
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// Canonicalize one header value: trim, fold runs of whitespace (incl.
/// newlines from multiline folding) to single spaces, inside quotes too,
/// per the suite's `get-header-value-trim`.
fn canonical_header_value(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

impl Signer {
    /// A signer for `service` in `region` (e.g. `("s3", "auto")` for R2).
    #[must_use]
    pub fn new(credentials: Credentials, region: String, service: String) -> Self {
        Self {
            credentials,
            region,
            service,
            key_cache: std::sync::Arc::default(),
        }
    }

    /// The derived signing key for `date` (`YYYYMMDD`), from the per-date
    /// cache when warm.
    ///
    /// # Errors
    /// The facade's HMAC key floor: `AWS4` + a secret access key below 112
    /// bits is refused under `fips` (the S3 backend refuses it at
    /// construction already).
    fn signing_key(
        &self,
        date: &str,
    ) -> Result<Zeroizing<[u8; 32]>, seaworthy_crypto::CryptoError> {
        let mut cache = self
            .key_cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((cached_date, key)) = cache.as_ref()
            && cached_date == date
        {
            return Ok(key.clone());
        }
        let secret = Zeroizing::new(
            format!("AWS4{}", self.credentials.secret_access_key.as_str()).into_bytes(),
        );
        let mut key = Zeroizing::new(hmac_sha256(&secret, date.as_bytes())?);
        for data in [self.region.as_str(), self.service.as_str(), "aws4_request"] {
            key = Zeroizing::new(hmac_sha256(key.as_slice(), data.as_bytes())?);
        }
        *cache = Some((date.to_owned(), key.clone()));
        Ok(key)
    }

    /// The credential scope date segment (`YYYYMMDD`).
    fn scope_date(amz_datetime: &str) -> &str {
        // "YYYYMMDDTHHMMSSZ": the date is the first 8 bytes.
        amz_datetime.get(..8).unwrap_or(amz_datetime)
    }

    /// The credential scope (`date/region/service/aws4_request`).
    #[must_use]
    pub fn scope(&self, amz_datetime: &str) -> String {
        format!(
            "{}/{}/{}/aws4_request",
            Self::scope_date(amz_datetime),
            self.region,
            self.service
        )
    }

    /// The request with the signer-added headers folded in: `x-amz-date`,
    /// `x-amz-content-sha256` when the request's `content_sha256_header`
    /// is set, `x-amz-security-token` when a session token is set.
    #[must_use]
    pub fn augment_for_header_mode<'a>(&self, req: &SignRequest<'a>) -> SignRequest<'a> {
        let mut full = req.clone();
        full.headers
            .push(("x-amz-date".to_owned(), req.amz_datetime.to_owned()));
        if req.content_sha256_header {
            let payload_hash = match req.payload {
                Payload::Sha256Hex(hash) => hash.to_owned(),
                Payload::Unsigned => UNSIGNED_PAYLOAD.to_owned(),
            };
            full.headers
                .push(("x-amz-content-sha256".to_owned(), payload_hash));
        }
        if let Some(token) = &self.credentials.session_token {
            full.headers
                .push(("x-amz-security-token".to_owned(), token.to_string()));
        }
        full
    }

    /// The canonical request for `req`, with every intermediate value
    /// exposed (the KAT harness compares `text` byte-for-byte).
    #[must_use]
    pub fn canonical_request(&self, req: &SignRequest<'_>) -> CanonicalRequest {
        let uri = canonical_uri(req.path, req.normalize_path);
        let query = canonical_query(&req.query);

        // Fold headers: lowercase names, canonical values, duplicates
        // comma-joined in order (get-header-key-duplicate), sorted by name.
        let mut folded: Vec<(String, String)> = Vec::new();
        let mut push_header = |name: &str, value: &str| {
            let name = name.to_ascii_lowercase();
            let value = canonical_header_value(value);
            if let Some((_, existing)) = folded.iter_mut().find(|(n, _)| *n == name) {
                existing.push(',');
                existing.push_str(&value);
            } else {
                folded.push((name, value));
            }
        };
        push_header("host", req.host);
        for (name, value) in &req.headers {
            push_header(name, value);
        }
        folded.sort_by(|a, b| a.0.cmp(&b.0));

        let headers = folded
            .iter()
            .map(|(n, v)| format!("{n}:{v}\n"))
            .collect::<String>();
        let signed_headers = folded
            .iter()
            .map(|(n, _)| n.as_str())
            .collect::<Vec<_>>()
            .join(";");
        let payload_hash = match req.payload {
            Payload::Sha256Hex(hash) => hash.to_owned(),
            Payload::Unsigned => UNSIGNED_PAYLOAD.to_owned(),
        };
        let text = format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            req.method, uri, query, headers, signed_headers, payload_hash
        );
        CanonicalRequest {
            uri,
            query,
            headers,
            signed_headers,
            payload_hash,
            text,
        }
    }

    /// The string to sign for a canonical request at `amz_datetime`.
    #[must_use]
    pub fn string_to_sign(&self, amz_datetime: &str, canonical_request: &str) -> String {
        format!(
            "AWS4-HMAC-SHA256\n{}\n{}\n{}",
            amz_datetime,
            self.scope(amz_datetime),
            digest::sha256_hex(canonical_request.as_bytes())
        )
    }

    /// The final signature for a string to sign.
    ///
    /// # Errors
    /// [`StorageError::Crypto`] when the facade refuses the HMAC key
    /// (`AWS4` + a secret access key below 112 bits under `fips`).
    pub fn signature(
        &self,
        amz_datetime: &str,
        string_to_sign: &str,
    ) -> Result<String, StorageError> {
        let key = self.signing_key(Self::scope_date(amz_datetime))?;
        Ok(hex::encode(hmac_sha256(
            key.as_slice(),
            string_to_sign.as_bytes(),
        )?))
    }

    /// Header-mode signing: the headers to ADD to the request
    /// (`x-amz-date`, `x-amz-content-sha256` when the request's
    /// `content_sha256_header` is set, `x-amz-security-token` when a
    /// session token is set, and `authorization`).
    ///
    /// # Errors
    /// As [`Self::signature`].
    pub fn signed_headers(
        &self,
        req: &SignRequest<'_>,
    ) -> Result<Vec<(String, String)>, StorageError> {
        let full = self.augment_for_header_mode(req);
        let canonical = self.canonical_request(&full);
        let sts = self.string_to_sign(req.amz_datetime, &canonical.text);
        let signature = self.signature(req.amz_datetime, &sts)?;

        let mut out = vec![("x-amz-date".to_owned(), req.amz_datetime.to_owned())];
        if req.content_sha256_header {
            out.push(("x-amz-content-sha256".to_owned(), canonical.payload_hash));
        }
        if let Some(token) = &self.credentials.session_token {
            out.push(("x-amz-security-token".to_owned(), token.to_string()));
        }
        out.push((
            "authorization".to_owned(),
            format!(
                "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
                self.credentials.access_key_id,
                self.scope(req.amz_datetime),
                canonical.signed_headers,
                signature
            ),
        ));
        Ok(out)
    }
}

/// The current UTC time in `YYYYMMDDTHHMMSSZ` form (tests inject fixed
/// timestamps instead).
#[must_use]
pub fn current_amz_datetime() -> String {
    amz_datetime(SystemTime::now())
}

/// `at` in SigV4's `YYYYMMDDTHHMMSSZ` form (UTC). A clock before the epoch
/// reads as the epoch (the request then fails the service's skew check,
/// loudly).
#[must_use]
pub fn amz_datetime(at: SystemTime) -> String {
    let seconds = at.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let (year, month, day) = civil_from_days(seconds / 86_400);
    let of_day = seconds % 86_400;
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        of_day / 3600,
        of_day % 3600 / 60,
        of_day % 60
    )
}

/// The proleptic Gregorian `(year, month, day)` of `days` since
/// 1970-01-01 (Howard Hinnant's civil-from-days, unsigned form; every
/// intermediate stays far inside `u64` for any `SystemTime`).
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days.saturating_add(719_468);
    let era = z / 146_097;
    let doe = z.saturating_sub(era.saturating_mul(146_097)); // [0, 146096]
    let yoe = doe
        .saturating_sub(doe / 1460)
        .saturating_add(doe / 36_524)
        .saturating_sub(doe / 146_096)
        / 365; // [0, 399]
    let doy = doe.saturating_sub(
        yoe.saturating_mul(365)
            .saturating_add(yoe / 4)
            .saturating_sub(yoe / 100),
    ); // [0, 365]
    let mp = doy.saturating_mul(5).saturating_add(2) / 153; // [0, 11]
    let day = doy
        .saturating_sub(mp.saturating_mul(153).saturating_add(2) / 5)
        .saturating_add(1); // [1, 31]
    let month = if mp < 10 {
        mp.saturating_add(3)
    } else {
        mp.saturating_sub(9)
    }; // [1, 12]
    let year = yoe
        .saturating_add(era.saturating_mul(400))
        .saturating_add(u64::from(month <= 2));
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn signer() -> Signer {
        Signer::new(
            Credentials {
                access_key_id: "AKIDEXAMPLE".to_owned(),
                secret_access_key: Zeroizing::new(
                    "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_owned(),
                ),
                session_token: None,
            },
            "us-east-1".to_owned(),
            "service".to_owned(),
        )
    }

    #[test]
    fn uri_encoding_alphabet() {
        assert_eq!(uri_encode("abcXYZ019-._~", false), "abcXYZ019-._~");
        assert_eq!(uri_encode("a/b", true), "a/b");
        assert_eq!(uri_encode("a/b", false), "a%2Fb");
        assert_eq!(uri_encode("a b", false), "a%20b");
        assert_eq!(uri_encode("$delete", true), "%24delete");
        assert_eq!(uri_encode("ሴ", true), "%E1%88%B4");
        assert_eq!(uri_encode("+", false), "%2B");
    }

    #[test]
    fn query_canonicalization_sorts_encoded_pairs() {
        // get-vanilla-query-order-encoded: sorting happens on the ENCODED
        // bytes.
        let query = vec![
            ("Param-3".to_owned(), "Value3".to_owned()),
            ("Param".to_owned(), "Value2".to_owned()),
            ("ሴ".to_owned(), "Value1".to_owned()),
        ];
        assert_eq!(
            canonical_query(&query),
            "%E1%88%B4=Value1&Param=Value2&Param-3=Value3"
        );
        // Duplicates survive and order by value.
        let dupes = vec![
            ("Param1".to_owned(), "value2".to_owned()),
            ("Param1".to_owned(), "value1".to_owned()),
        ];
        assert_eq!(canonical_query(&dupes), "Param1=value1&Param1=value2");
    }

    #[test]
    fn header_values_fold_whitespace() {
        assert_eq!(canonical_header_value("  value1   "), "value1");
        assert_eq!(canonical_header_value("value1\n  value2"), "value1 value2");
        assert_eq!(canonical_header_value("\"a   b   c\""), "\"a b c\"");
    }

    #[test]
    fn path_normalization_matches_the_suite() {
        assert_eq!(normalize_path("/example/.."), "/");
        assert_eq!(normalize_path("/example1/example2/../.."), "/");
        assert_eq!(normalize_path("//"), "/");
        assert_eq!(normalize_path("/./"), "/");
        assert_eq!(normalize_path("/./example"), "/example");
        assert_eq!(normalize_path("//example//"), "/example/");
        assert_eq!(normalize_path("/example space/"), "/example space/");
        assert_eq!(normalize_path("/example/$delete"), "/example/$delete");
    }

    #[test]
    fn derived_key_chain_matches_aws_docs() {
        // The worked example from the AWS SigV4 documentation
        // ("Examples of how to derive a signing key"): secret
        // wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY, 20120215, us-east-1, iam.
        let signer = Signer::new(
            Credentials {
                access_key_id: "AKIDEXAMPLE".to_owned(),
                secret_access_key: Zeroizing::new(
                    "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".to_owned(),
                ),
                session_token: None,
            },
            "us-east-1".to_owned(),
            "iam".to_owned(),
        );
        // The documented kSigning, through the private derivation.
        assert_eq!(
            hex::encode(*signer.signing_key("20120215").expect("derive")),
            "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"
        );
        // And a full signature over it is well-formed (the KAT suite covers
        // the byte-exact paths; this pins the region/service folding order).
        let sig = signer.signature(
            "20120215T000000Z",
            "AWS4-HMAC-SHA256\n20120215T000000Z\n20120215/us-east-1/iam/aws4_request\nbc58b3c15a5b2e6f51fe0bff48b15f4fe8ddfe671e3e39b3b4b5dd6d60ba2ba2",
        ).expect("sign");
        assert_eq!(sig.len(), 64);
        assert!(sig.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn signing_key_is_cached_per_scope_date() {
        // The derived key is computed once per UTC date, and the cached
        // path signs identically to a cold one.
        let signer = signer();
        let sts =
            "AWS4-HMAC-SHA256\n20150830T123600Z\n20150830/us-east-1/service/aws4_request\nabc";
        let cold = signer.signature("20150830T123600Z", sts).expect("sign");
        assert_eq!(
            signer
                .key_cache
                .lock()
                .expect("cache")
                .as_ref()
                .map(|(date, _)| date.clone())
                .as_deref(),
            Some("20150830")
        );
        let warm = signer.signature("20150830T235959Z", sts).expect("sign");
        assert_eq!(cold, warm, "same date, same key");
        assert_eq!(
            cold,
            super::Signer::new(
                signer.credentials.clone(),
                "us-east-1".to_owned(),
                "service".to_owned()
            )
            .signature("20150830T000000Z", sts)
            .expect("sign")
        );
        // A new date re-derives (and the key differs).
        let next_day = signer.signature("20150831T000000Z", sts).expect("sign");
        assert_ne!(cold, next_day);
    }

    #[test]
    fn debug_output_never_carries_the_secret_or_the_session_token() {
        let mut credentials = signer().credentials;
        credentials.session_token = Some(Zeroizing::new("FwoGZXIvYXdzEXAMPLETOKEN".to_owned()));
        let signer = Signer::new(credentials, "auto".to_owned(), "s3".to_owned());
        let rendered = format!("{signer:?} {:?}", signer.credentials);
        assert!(!rendered.contains("wJalrXUtnFEMI"), "{rendered}");
        assert!(!rendered.contains("EXAMPLETOKEN"), "{rendered}");
        assert!(
            rendered.contains("AKIDEXAMPLE"),
            "the key id is not a secret"
        );
        assert!(rendered.contains("session_token: true"), "{rendered}");
    }

    #[test]
    fn the_session_token_is_signed_and_sent() {
        let mut credentials = signer().credentials;
        credentials.session_token = Some(Zeroizing::new("token-value".to_owned()));
        let signer = Signer::new(credentials, "us-east-1".to_owned(), "s3".to_owned());
        let request = SignRequest {
            method: "GET",
            host: "example.com",
            path: "/bucket/key",
            query: Vec::new(),
            headers: Vec::new(),
            payload: Payload::Sha256Hex(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            normalize_path: false,
            content_sha256_header: true,
            amz_datetime: "20150830T123600Z",
        };
        let headers = signer.signed_headers(&request).expect("sign");
        assert!(
            headers
                .iter()
                .any(|(n, v)| n == "x-amz-security-token" && v == "token-value")
        );
        let authz = headers
            .iter()
            .find(|(n, _)| n == "authorization")
            .map(|(_, v)| v.as_str())
            .expect("authorization");
        assert!(
            authz.contains(
                "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token,"
            ),
            "{authz}"
        );
    }

    #[test]
    fn amz_datetime_formats_utc() {
        let at = |seconds: u64| amz_datetime(UNIX_EPOCH + Duration::from_secs(seconds));
        assert_eq!(at(0), "19700101T000000Z");
        assert_eq!(at(1_440_938_160), "20150830T123600Z", "the suite's instant");
        assert_eq!(at(951_782_400), "20000229T000000Z", "a leap day");
        assert_eq!(at(951_868_799), "20000229T235959Z");
        assert_eq!(at(951_868_800), "20000301T000000Z");
        assert_eq!(at(1_791_979_200), "20261014T120000Z");
        assert_eq!(at(4_102_444_799), "20991231T235959Z");
        assert_eq!(
            at(4_107_542_400),
            "21000301T000000Z",
            "2100 is not a leap year"
        );
        assert_eq!(
            amz_datetime(UNIX_EPOCH - Duration::from_secs(1)),
            "19700101T000000Z",
            "a pre-epoch clock reads as the epoch"
        );
        let now = current_amz_datetime();
        assert_eq!(now.len(), 16);
        assert!(now.starts_with("20") && now.ends_with('Z'), "{now}");
    }
}
