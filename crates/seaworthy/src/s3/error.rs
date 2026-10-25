//! [`StorageError`], the one error type of the S3 client, and the bounded
//! classification of a non-2xx response into it.

use futures_util::StreamExt as _;

/// The canonical error type for every S3 operation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StorageError {
    /// A path failed [`super::StoragePath`] validation.
    #[error("invalid storage path: {0}")]
    InvalidPath(String),

    /// The HTTP request returned a non-success status without a parseable
    /// S3 error document.
    #[error("http request failed with status {status_code}: {error_text}")]
    Http {
        /// The HTTP status code (`0` for a refusal before any request).
        status_code: u16,
        /// The raw error body (truncated, control characters stripped).
        error_text: String,
    },

    /// The S3 API returned a structured error document.
    #[error("s3 error {code}: {message}")]
    S3 {
        /// The S3 error code (`NoSuchKey`, `SignatureDoesNotMatch`, …).
        code: String,
        /// The human-readable message.
        message: String,
    },

    /// A request or configuration violates a hard bound (endpoint shape,
    /// bucket or region grammar, a body or header over its cap). Never
    /// retryable: the request itself is out of contract.
    #[error("validation failed: {0}")]
    Validation(String),

    /// An operation exceeded its configured deadline
    /// (`S3Config::management_timeout`, `PutOptions::timeout`). Transient:
    /// safe to retry.
    #[error("operation timed out")]
    Timeout,

    /// The stored/delivered object's SHA-256 does not match the one the
    /// write committed to (a service echoing another checksum) or the one
    /// the service stored (a read).
    #[error("object hash does not match the expected sha256")]
    HashMismatch,

    /// The crypto facade failed (or refused a key: the HMAC key floor
    /// under `fips`).
    #[error("crypto error: {0}")]
    Crypto(#[from] seaworthy_crypto::CryptoError),

    /// An XML shape from the storage service did not parse.
    #[error("xml error: {0}")]
    Xml(String),

    /// A network/transport failure from the HTTP stack. Constructed only
    /// through `StorageError::transport`, which strips the request URL: a
    /// URL never reaches an error message or log line (the S3 client signs
    /// in headers, but the rule keeps any future query-signed URL out too).
    #[error("http transport error: {0}")]
    Transport(reqwest::Error),
}

impl StorageError {
    /// Convert a reqwest error, stripping the request URL first. The
    /// URL-less kind/context of the error is preserved.
    pub(crate) fn transport(error: reqwest::Error) -> Self {
        Self::Transport(error.without_url())
    }

    /// Whether the error is a transient fault safe for automated retry:
    /// HTTP 408/429/5xx and transport-level severance, never 4xx, never
    /// integrity failures.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Http { status_code, .. } => {
                matches!(status_code, 408 | 429 | 500 | 502 | 503 | 504)
            }
            Self::S3 { code, .. } => matches!(
                code.as_str(),
                "RequestTimeout"
                    | "RequestTimeoutException"
                    | "SlowDown"
                    | "InternalError"
                    | "ServiceUnavailable"
                    | "Throttling"
                    | "ThrottlingException"
                    // A concurrent conditional write raced this one (S3's
                    // `409` for `If-None-Match`): retry, and the create-only
                    // answer decides.
                    | "ConditionalRequestConflict"
            ),
            Self::Transport(_) | Self::Timeout => true,
            _ => false,
        }
    }
}

/// Strip EVERY ASCII control character (C0 0x00–0x1F and DEL 0x7F) from an
/// endpoint-controlled string before it crosses into an error/log line: a
/// hostile endpoint must not forge log lines through a rendered
/// [`StorageError`]. (Log-line sanitizing is a private helper per crate.)
pub(crate) fn line_safe(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(c, '\u{0}'..='\u{1f}' | '\u{7f}'))
        .collect()
}

/// The cap for error response bodies (64 KiB), read-bounded BEFORE any
/// truncation: a hostile endpoint's 1 GiB "error" is neither buffered nor
/// awaited in full.
pub(crate) const MAX_ERROR_BODY_BYTES: usize = 64 * 1024;

/// Read an error response's body (bounded) and classify it.
pub(crate) async fn error_from_response(response: reqwest::Response) -> StorageError {
    let status_code = response.status().as_u16();
    let mut stream = response.bytes_stream();
    let mut body: Vec<u8> = Vec::new();
    let mut read_failed = false;
    // The cap is checked BEFORE awaiting the next chunk. Checking it only
    // after a chunk arrives waits for bytes past a full cap: a peer that
    // sends exactly the cap and stalls would hold the read until the
    // transport timeout.
    while body.len() < MAX_ERROR_BODY_BYTES {
        let Some(chunk) = stream.next().await else {
            break; // end of body
        };
        let Ok(chunk) = chunk else {
            read_failed = true;
            break;
        };
        let room = MAX_ERROR_BODY_BYTES.saturating_sub(body.len());
        body.extend(chunk.iter().take(room));
    }
    // Cap reached (or the body ended): the rest is dropped unread.
    let text = if body.is_empty() && read_failed {
        "<failed to read error body>".to_owned()
    } else {
        String::from_utf8_lossy(&body).into_owned()
    };
    // Parse the FULL bounded body: pre-truncating could cut mid-element
    // and degrade the typed `S3` classification (the retry taxonomy rides
    // it) to a generic `Http`. Truncation is the human-facing fallback's
    // business only.
    if let Some(shape) = super::xml::parse_error(&text) {
        return StorageError::S3 {
            code: line_safe(&shape.code),
            message: line_safe(&shape.message),
        };
    }
    // Endpoint-controlled strings are control-character-stripped at this
    // trust boundary.
    let truncated: String = text.chars().take(2048).collect();
    StorageError::Http {
        status_code,
        error_text: line_safe(&truncated),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_safe_strips_every_control_character() {
        assert_eq!(line_safe("a\r\nb\tc\u{0}d\u{1b}[31me\u{7f}f"), "abcd[31mef");
        assert_eq!(line_safe("plain text: ok"), "plain text: ok");
        assert_eq!(line_safe("ünïcödé"), "ünïcödé", "only ASCII controls go");
    }

    #[test]
    fn the_retry_taxonomy_retries_transient_faults_only() {
        let http = |status_code| StorageError::Http {
            status_code,
            error_text: String::new(),
        };
        let s3 = |code: &str| StorageError::S3 {
            code: code.to_owned(),
            message: String::new(),
        };
        for status in [408, 429, 500, 502, 503, 504] {
            assert!(http(status).is_retryable(), "{status}");
        }
        for status in [0, 400, 401, 403, 404, 409, 412, 501] {
            assert!(!http(status).is_retryable(), "{status}");
        }
        for code in ["SlowDown", "InternalError", "ConditionalRequestConflict"] {
            assert!(s3(code).is_retryable(), "{code}");
        }
        for code in [
            "AccessDenied",
            "NoSuchKey",
            "SignatureDoesNotMatch",
            "BadDigest",
        ] {
            assert!(!s3(code).is_retryable(), "{code}");
        }
        assert!(StorageError::Timeout.is_retryable());
        assert!(!StorageError::HashMismatch.is_retryable());
        assert!(!StorageError::Validation(String::new()).is_retryable());
    }
}
