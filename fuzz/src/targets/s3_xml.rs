//! `s3_xml` — the S3 publish client's parsers of store-controlled input:
//! the `ListObjectsV2` page and the S3 `Error` document (`seaworthy::s3::xml`),
//! a listing's `LastModified` as `publish` reads it, plus the key
//! validation and the SigV4 encoding every request rides on.
//!
//! Input: `[mode][bytes]`.
//!
//! Invariants:
//! - the XML parsers never panic on any document; `parse_error` answers
//!   only for documents that claim to be an `Error`;
//! - a parsed page or error document, written back out canonically
//!   (escaped), parses to exactly the same values: no value is truncated,
//!   split at an entity, or decoded twice;
//! - `publish::parse_iso8601` never panics and never answers a time past
//!   the year 9999;
//! - `StoragePath::new` is idempotent and every accepted path satisfies the
//!   portability rules (independent re-check);
//! - `sigv4::uri_encode` emits only unreserved characters and uppercase
//!   `%XX` escapes (plus `/` when kept) and percent-decodes back to its
//!   input;
//! - a signed request's canonical headers never fold into a blank line,
//!   name each header once, sorted, and its authorization ends in a
//!   64-hex-digit signature.

use arbitrary::{Arbitrary, Unstructured};
use seaworthy::s3::sigv4::{self, Credentials, Payload, SignRequest, Signer};
use seaworthy::s3::xml::{self, ListResult};
use seaworthy::s3::StoragePath;

pub fn run(data: &[u8]) {
    let Some((&mode, bytes)) = data.split_first() else {
        return;
    };
    let text = crate::text(bytes);
    match mode % 5 {
        0 => xml_documents(&text),
        1 => storage_path(&text),
        2 => {
            uri_encoding(&text, true);
            uri_encoding(&text, false);
        }
        3 => last_modified(&text),
        _ => signing(bytes),
    }
}

fn xml_documents(text: &str) {
    if let Some(error) = xml::parse_error(text) {
        assert!(
            text.contains("<Error"),
            "only an Error document parses as one"
        );
        // An empty code can only have come from an empty CDATA section:
        // written back the same way (an empty element carries no value).
        let code = if error.code.is_empty() {
            "<![CDATA[]]>".to_owned()
        } else {
            escape(&error.code)
        };
        let again = format!(
            "<Error><Code>{code}</Code><Message>{}</Message></Error>",
            escape(&error.message)
        );
        assert_eq!(
            xml::parse_error(&again).as_ref(),
            Some(&error),
            "the error document written back reads the same: {again:?}"
        );
    }
    if let Ok(page) = xml::parse_list_objects_v2(text) {
        for object in &page.objects {
            if let Some(modified) = &object.last_modified {
                last_modified(modified);
            }
            let _ = StoragePath::new(&object.key);
        }
        let again = write_page(&page);
        assert_eq!(
            xml::parse_list_objects_v2(&again).ok().as_ref(),
            Some(&page),
            "the page written back reads the same: {again:?}"
        );
    }
}

/// Text for an element's content, as an S3 store would write it: the five
/// predefined entities, and a carriage return as a character reference (a
/// raw one reads back as a line feed, by XML's end-of-line rule).
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\r' => out.push_str("&#xD;"),
            c => out.push(c),
        }
    }
    out
}

/// `page` as a `ListObjectsV2` document.
fn write_page(page: &ListResult) -> String {
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult>");
    out.push_str(&format!(
        "<IsTruncated>{}</IsTruncated>",
        page.is_truncated
    ));
    if let Some(token) = &page.next_continuation_token {
        out.push_str(&format!(
            "<NextContinuationToken>{}</NextContinuationToken>",
            escape(token)
        ));
    }
    for object in &page.objects {
        out.push_str("<Contents>");
        out.push_str(&format!("<Key>{}</Key>", escape(&object.key)));
        if let Some(modified) = &object.last_modified {
            out.push_str(&format!(
                "<LastModified>{}</LastModified>",
                escape(modified)
            ));
        }
        if let Some(etag) = &object.etag {
            out.push_str(&format!("<ETag>{}</ETag>", escape(etag)));
        }
        out.push_str(&format!("<Size>{}</Size>", object.size));
        out.push_str("</Contents>");
    }
    out.push_str("</ListBucketResult>");
    out
}

fn last_modified(text: &str) {
    // 9999-12-31T23:59:60Z, the latest time the parser's ranges allow.
    const LATEST: u64 = 253_402_300_800;
    if let Some(seconds) = seaworthy::publish::parse_iso8601(text) {
        assert!(seconds <= LATEST, "{text:?} read as {seconds}");
        assert!(text.ends_with('Z') && text.contains('T'), "{text:?}");
    }
}

fn storage_path(text: &str) {
    let Ok(path) = StoragePath::new(text) else {
        return;
    };
    assert_eq!(path.as_str(), text);
    assert_eq!(
        StoragePath::new(path.as_str()).ok().as_ref(),
        Some(&path),
        "idempotent"
    );
    assert!(text.is_ascii() && !text.starts_with('/') && !text.ends_with('/'));
    let segments: Vec<&str> = path.segments().collect();
    assert!(!segments.is_empty());
    for segment in &segments {
        assert!(!segment.is_empty() && *segment != "." && *segment != "..");
        assert!(
            !segment
                .bytes()
                .any(|b| b <= 0x1f || b == 0x7f || b"<>:\"|?*\\".contains(&b)),
            "{segment:?}"
        );
        assert!(!segment.ends_with(['.', ' ']), "{segment:?}");
    }
    assert_eq!(path.file_name(), *segments.last().unwrap());
}

fn uri_encoding(text: &str, keep_slash: bool) {
    let encoded = sigv4::uri_encode(text, keep_slash);
    let bytes = encoded.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if b == b'%' {
            let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).expect("escape is ASCII");
            assert!(
                hex.bytes()
                    .all(|h| h.is_ascii_digit() || (b'A'..=b'F').contains(&h)),
                "SigV4 escapes are uppercase hex"
            );
            decoded.push(u8::from_str_radix(hex, 16).unwrap());
            i += 3;
        } else {
            assert!(
                b.is_ascii_alphanumeric()
                    || matches!(b, b'-' | b'_' | b'.' | b'~')
                    || (keep_slash && b == b'/'),
                "unescaped reserved byte {b:#04x}"
            );
            decoded.push(b);
            i += 1;
        }
    }
    assert_eq!(decoded, text.as_bytes(), "uri_encode must round-trip");
}

#[derive(Arbitrary, Debug)]
struct SignInput {
    path: String,
    query: Vec<(String, String)>,
    header: String,
    datetime: String,
    region: String,
    token: Option<String>,
    payload: Option<String>,
    normalize: bool,
    content_sha256: bool,
}

fn signing(bytes: &[u8]) {
    let Ok(input) = SignInput::arbitrary_take_rest(Unstructured::new(bytes)) else {
        return;
    };
    let signer = Signer::new(
        Credentials {
            access_key_id: "AKIDFUZZ".to_owned(),
            secret_access_key: "fuzz-secret-access-key-material".to_owned().into(),
            session_token: input.token.clone().map(Into::into),
        },
        input.region.clone(),
        "s3".to_owned(),
    );
    let request = SignRequest {
        method: "GET",
        host: "files.example.com",
        path: &input.path,
        query: input.query.clone(),
        headers: vec![("x-fuzz".to_owned(), input.header.clone())],
        payload: input
            .payload
            .as_deref()
            .map_or(Payload::Unsigned, Payload::Sha256Hex),
        normalize_path: input.normalize,
        content_sha256_header: input.content_sha256,
        amz_datetime: &input.datetime,
    };
    let full = signer.augment_for_header_mode(&request);
    let canonical = signer.canonical_request(&full);
    assert!(
        !canonical.headers.contains("\n\n"),
        "header values never fold into a blank line"
    );
    let names: Vec<&str> = canonical.signed_headers.split(';').collect();
    assert!(
        names.windows(2).all(|pair| pair[0] < pair[1]),
        "each header once, sorted: {names:?}"
    );
    assert_eq!(canonical.headers.lines().count(), names.len());
    for name in ["host", "x-amz-date", "x-fuzz"] {
        assert!(names.contains(&name), "{name} is signed: {names:?}");
    }
    assert!(canonical.query.split('&').all(|pair| pair.is_empty() || pair.contains('=')));
    let Ok(headers) = signer.signed_headers(&request) else {
        return;
    };
    let authorization = headers
        .iter()
        .find(|(name, _)| name == "authorization")
        .map(|(_, value)| value)
        .expect("an authorization header");
    let (_, signature) = authorization
        .rsplit_once(", Signature=")
        .expect("the signature is last");
    assert_eq!(signature.len(), 64);
    assert!(
        signature
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
}
