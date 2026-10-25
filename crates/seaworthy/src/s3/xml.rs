//! The S3 XML shapes the client reads: `ListObjectsV2` and the S3 `Error`
//! document. Parsing is quick-xml with entity resolution: every value is
//! the JOIN of its text pieces and entity references (the reader reports
//! `&amp;` as its own event, so a parser keeping only the last piece would
//! truncate values). quick-xml never fetches external entities or expands
//! a DTD: only the predefined entities and character references resolve.
//! Every body reaching these parsers is already size-bounded by the caller
//! (`MAX_XML_BODY_BYTES`, `MAX_ERROR_BODY_BYTES`).

use quick_xml::Reader;
use quick_xml::events::Event;

use super::StorageError;

fn xml_err(context: &'static str) -> StorageError {
    StorageError::Xml(context.to_owned())
}

/// Unescape one raw text node (entities like `&amp;`, EOL-normalized).
fn text_of(event: &quick_xml::events::BytesText<'_>) -> Result<String, StorageError> {
    quick_xml::escape::unescape(event.xml10_content().as_ref())
        .map(|text| text.into_owned())
        .map_err(|_| xml_err("malformed XML entity"))
}

/// The text one general entity or character reference stands for (`&amp;`
/// → `&`, `&#x26;` → `&`). The reader reports a reference as its OWN event
/// between the text pieces around it (the element's value is the
/// concatenation); an unknown entity is malformed.
fn ref_text(reference: &quick_xml::events::BytesRef<'_>) -> Result<String, StorageError> {
    let name: &str = reference.as_ref();
    quick_xml::escape::unescape(&format!("&{name};"))
        .map(|text| text.into_owned())
        .map_err(|_| xml_err("malformed XML entity"))
}

/// Fold every `<name>text</name>` of a flat-enough XML document (S3's
/// error document is) into `visit(name, text)`, once per element with its
/// WHOLE value: text pieces, entity references and CDATA concatenated,
/// entity-unescaped. An element with no text is not visited.
fn for_each_text(xml: &str, mut visit: impl FnMut(&str, &str)) -> Result<(), StorageError> {
    let mut reader = Reader::from_str(xml);
    let mut current: Option<(String, Option<String>)> = None;
    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) => {
                current = Some((element.local_name().as_ref().to_owned(), None));
            }
            Ok(Event::Text(text)) => {
                if let Some((_, value)) = current.as_mut() {
                    value
                        .get_or_insert_with(String::new)
                        .push_str(&text_of(&text)?);
                }
            }
            Ok(Event::GeneralRef(reference)) => {
                if let Some((_, value)) = current.as_mut() {
                    value
                        .get_or_insert_with(String::new)
                        .push_str(&ref_text(&reference)?);
                }
            }
            Ok(Event::CData(text)) => {
                if let Some((_, value)) = current.as_mut() {
                    value
                        .get_or_insert_with(String::new)
                        .push_str(&text.into_inner());
                }
            }
            Ok(Event::End(_)) => {
                if let Some((name, Some(value))) = current.take() {
                    visit(&name, &value);
                }
            }
            Ok(Event::Eof) => return Ok(()),
            Err(_) => return Err(xml_err("malformed XML from the storage service")),
            _ => {}
        }
    }
}

/// The S3 `Error` document's two fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct S3ErrorShape {
    /// The S3 error code (`NoSuchKey`, `SignatureDoesNotMatch`, …).
    pub code: String,
    /// The human-readable message.
    pub message: String,
}

/// Parse an S3 `Error` document; `None` when it isn't one (some services
/// answer errors with HTML or nothing).
#[must_use]
pub fn parse_error(xml: &str) -> Option<S3ErrorShape> {
    if !xml.contains("<Error") {
        return None;
    }
    let mut code = None;
    let mut message = None;
    for_each_text(xml, |name, text| match name {
        "Code" => code = Some(text.to_owned()),
        "Message" => message = Some(text.to_owned()),
        _ => {}
    })
    .ok()?;
    Some(S3ErrorShape {
        code: code?,
        message: message.unwrap_or_default(),
    })
}

/// One `Contents` entry from a `ListObjectsV2` page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListedKey {
    /// The object key (the FULL key, prefix included).
    pub key: String,
    /// The size in bytes.
    pub size: u64,
    /// The ETag (verbatim, quotes preserved).
    pub etag: Option<String>,
    /// The `LastModified` timestamp as reported (ISO 8601).
    pub last_modified: Option<String>,
}

/// A parsed `ListObjectsV2` page.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ListResult {
    /// The page's objects.
    pub objects: Vec<ListedKey>,
    /// Whether the server says more pages exist.
    pub is_truncated: bool,
    /// The continuation token for the next page.
    pub next_continuation_token: Option<String>,
}

/// Parse a `ListObjectsV2` response.
///
/// # Errors
/// [`StorageError::Xml`] on malformed XML.
pub fn parse_list_objects_v2(xml: &str) -> Result<ListResult, StorageError> {
    let mut result = ListResult::default();
    let mut in_contents = false;
    let mut current: Option<ListedKey> = None;

    let mut reader = Reader::from_str(xml);
    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) => {
                let name = element.local_name();
                match name.as_ref() {
                    "Contents" => {
                        in_contents = true;
                        current = Some(ListedKey {
                            key: String::new(),
                            size: 0,
                            etag: None,
                            last_modified: None,
                        });
                    }
                    "Key" | "Size" | "ETag" | "LastModified" if in_contents => {
                        let text = reader
                            .read_text(element.name())
                            .map_err(|_| xml_err("malformed ListObjectsV2 Contents"))?;
                        let text = text_of(&text)?;
                        if let Some(object) = current.as_mut() {
                            match name.as_ref() {
                                "Key" => object.key = text,
                                "Size" => {
                                    object.size = text
                                        .parse()
                                        .map_err(|_| xml_err("ListObjectsV2 Size is not u64"))?;
                                }
                                "ETag" => object.etag = Some(text),
                                "LastModified" => object.last_modified = Some(text),
                                _ => {}
                            }
                        }
                    }
                    "IsTruncated" | "NextContinuationToken" if !in_contents => {
                        let text = reader
                            .read_text(element.name())
                            .map_err(|_| xml_err("malformed ListObjectsV2 page"))?;
                        let text = text_of(&text)?;
                        if name.as_ref() == "IsTruncated" {
                            result.is_truncated = text == "true";
                        } else {
                            result.next_continuation_token = Some(text);
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::End(element)) => {
                if element.local_name().as_ref() == "Contents" {
                    in_contents = false;
                    if let Some(object) = current.take() {
                        result.objects.push(object);
                    }
                }
            }
            Ok(Event::Eof) => return Ok(result),
            Err(_) => return Err(xml_err("malformed XML from the storage service")),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_objects_v2_parses_pages() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>bucket</Name>
  <Prefix>scans/</Prefix>
  <KeyCount>2</KeyCount>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>true</IsTruncated>
  <NextContinuationToken>1ueGcxLPRx1Tr/XYExHnhbYLgveDs2J/wm36Hy4vbOwM=</NextContinuationToken>
  <Contents>
    <Key>scans/a&amp;b.txt</Key>
    <LastModified>2026-09-04T12:00:00.000Z</LastModified>
    <ETag>&quot;70ee1738b6b21e2c8a43f3a5ab0eee71&quot;</ETag>
    <Size>11</Size>
    <StorageClass>STANDARD</StorageClass>
  </Contents>
  <Contents>
    <Key>scans/empty.bin</Key>
    <LastModified>2026-09-04T12:01:00.000Z</LastModified>
    <ETag>"d41d8cd98f00b204e9800998ecf8427e"</ETag>
    <Size>0</Size>
    <StorageClass>STANDARD</StorageClass>
  </Contents>
</ListBucketResult>"#;
        let page = parse_list_objects_v2(xml).expect("parses");
        assert_eq!(page.objects.len(), 2);
        assert_eq!(page.objects[0].key, "scans/a&b.txt", "entities decoded");
        assert_eq!(
            page.objects[0].etag.as_deref(),
            Some("\"70ee1738b6b21e2c8a43f3a5ab0eee71\""),
            "ETag quotes preserved"
        );
        assert_eq!(
            page.objects[0].last_modified.as_deref(),
            Some("2026-09-04T12:00:00.000Z")
        );
        assert_eq!(page.objects[1].size, 0);
        assert!(page.is_truncated);
        assert!(page.next_continuation_token.is_some());
    }

    #[test]
    fn list_objects_v2_refuses_malformed_pages() {
        for bad in [
            "<ListBucketResult><Contents><Key>a</Key><Size>-1</Size></Contents></ListBucketResult>",
            "<ListBucketResult><Contents><Key>a</Key><Size>99999999999999999999</Size></Contents></ListBucketResult>",
            "<ListBucketResult><Contents><Key>a&bogus;</Key></Contents></ListBucketResult>",
            "<ListBucketResult><Contents><Key>a</Size></Contents></ListBucketResult>",
        ] {
            assert!(
                matches!(parse_list_objects_v2(bad), Err(StorageError::Xml(_))),
                "{bad}"
            );
        }
        // No external entity is ever resolved (quick-xml has no DTD
        // expansion): an entity declared in a DOCTYPE stays unknown.
        let xxe = "<!DOCTYPE l [<!ENTITY x SYSTEM \"file:///etc/passwd\">]>\
                   <ListBucketResult><Contents><Key>&x;</Key></Contents></ListBucketResult>";
        assert!(matches!(
            parse_list_objects_v2(xxe),
            Err(StorageError::Xml(_))
        ));
    }

    #[test]
    fn s3_error_shape() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message><Key>nope</Key></Error>"#;
        let error = parse_error(xml).expect("is an error doc");
        assert_eq!(error.code, "NoSuchKey");
        assert_eq!(error.message, "The specified key does not exist.");
        assert!(parse_error("<ListBucketResult/>").is_none());
        assert!(parse_error("").is_none());
        assert!(
            parse_error("<Error><Message>no code</Message></Error>").is_none(),
            "an error document without a code is not one"
        );
    }

    /// The reader reports an entity reference as its own event between text
    /// pieces; the parser joins them (an error message must not read as its
    /// last piece).
    #[test]
    fn values_split_by_entity_references_are_joined() {
        let err = "<Error><Code>A&amp;B</Code><Message>x &lt; y</Message></Error>";
        let shape = parse_error(err).expect("error shape");
        assert_eq!(shape.code, "A&B");
        assert_eq!(shape.message, "x < y");
        let numeric = "<Error><Code>Bad&#x26;Code</Code><Message>m</Message></Error>";
        assert_eq!(parse_error(numeric).expect("shape").code, "Bad&Code");
        let cdata = "<Error><Code>C</Code><Message><![CDATA[a <b>]]> c</Message></Error>";
        assert_eq!(parse_error(cdata).expect("shape").message, "a <b> c");
    }
}
