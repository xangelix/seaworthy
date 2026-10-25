//! The bounded, TLS-enforced download path: the TLS gate, the redirect
//! policy, metadata (the manifest, a package signature) fetches, and the
//! package download into the staged file.

use std::sync::Arc;
use std::time::Duration;

use crate::{MAX_ARTIFACT_BYTES, MAX_METADATA_BYTES, UpdateError};

/// Connect fails fast when the release host is down.
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);
/// Whole-transfer ceiling for the PACKAGE (headers + body); the helper
/// lowers it to its own budget (`helper::DOWNLOAD_TIMEOUT`).
pub(crate) const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// Whole-transfer ceiling for a METADATA fetch: a slow-drip 64 KiB
/// body must not hold a run for the package download's whole budget.
pub(crate) const METADATA_TIMEOUT: Duration = Duration::from_secs(60);

/// The download bounds applied to one update.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Limits {
    pub(crate) max_artifact_bytes: u64,
    pub(crate) max_metadata_bytes: u64,
    pub(crate) connect_timeout: Duration,
    pub(crate) download_timeout: Duration,
    pub(crate) metadata_timeout: Duration,
    /// Exact hosts a redirect may lead to; empty = no redirects.
    pub(crate) redirect_hosts: Arc<[String]>,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_artifact_bytes: MAX_ARTIFACT_BYTES,
            max_metadata_bytes: MAX_METADATA_BYTES,
            connect_timeout: CONNECT_TIMEOUT,
            download_timeout: DOWNLOAD_TIMEOUT,
            metadata_timeout: METADATA_TIMEOUT,
            redirect_hosts: Arc::from(Vec::new()),
        }
    }
}

/// Wrap a reqwest error with its URL stripped: reqwest's `Display` formats
/// `error sending request for url ({url})`, and the URL may be a presigned
/// GET carrying credentials in its query string — a bearer token must never
/// reach an error string, a log line, or a tracing event. Every reqwest
/// error site routes through here.
pub(crate) fn http_err(error: reqwest::Error) -> UpdateError {
    UpdateError::Http(error.without_url())
}

/// Redirect discipline, as a pure decision. Redirects are REFUSED
/// unless the hop's host is on the exact-host allowlist
/// (`HelperConfig::allow_redirect_hosts`: CDN and presigned-redirect flows), so
/// an untrusted origin cannot turn the fleet into a blind GET SSRF /
/// distributed-flood primitive against arbitrary https hosts. Inside the
/// allowlist the no-downgrade rule still holds: https hops always, a
/// plaintext hop only to a loopback host and only when the chain started on
/// plaintext loopback (the test suite and dev rigs). `previous` is the
/// chain's already-requested URLs (`previous[0]` = the initial URL).
pub(crate) fn redirect_permitted(
    allowed_hosts: &[String],
    previous: &[reqwest::Url],
    target: &reqwest::Url,
) -> bool {
    let Some(host) = target.host_str() else {
        return false;
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if !allowed_hosts
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(host))
    {
        return false;
    }
    if target.scheme() == "https" {
        return true;
    }
    target.scheme() == "http"
        && is_loopback_url(target)
        && previous
            .first()
            .is_some_and(|initial| initial.scheme() == "http" && is_loopback_url(initial))
}

/// A reqwest client on the workspace-standard rustls provider, bounded:
/// connect fails fast, the whole transfer is time-capped (`total_timeout`),
/// and redirects follow [`redirect_permitted`].
fn http_client(limits: &Limits, total_timeout: Duration) -> Result<reqwest::Client, UpdateError> {
    use rustls_platform_verifier::BuilderVerifierExt as _;
    // seaworthy-crypto's canonical provider (FIPS-restricted under
    // `seaworthy-crypto/fips`) shaped by the process's TLS policy,
    // preconfigured: never whatever process default happens to be set.
    let tls = seaworthy_crypto::tls::client_config_builder()
        .and_then(|builder| builder.with_platform_verifier())
        // A TLS stack that cannot initialize (the platform verifier) is a
        // typed error, never a panic.
        .map_err(|e| UpdateError::Io(std::io::Error::other(format!("tls configuration: {e}"))))?
        .with_no_client_auth();
    let allowed = Arc::clone(&limits.redirect_hosts);
    let policy = if allowed.is_empty() {
        reqwest::redirect::Policy::none()
    } else {
        reqwest::redirect::Policy::custom(move |attempt| {
            if redirect_permitted(&allowed, attempt.previous(), attempt.url()) {
                // Compose with the default policy to keep its 10-hop cap.
                reqwest::redirect::Policy::default().redirect(attempt)
            } else {
                attempt.error("redirect to a host outside the allowlist refused")
            }
        })
    };
    reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .connect_timeout(limits.connect_timeout)
        .timeout(total_timeout)
        .redirect(policy)
        .build()
        // Timeouts + a redirect policy only; a refusal (a TLS backend that
        // cannot initialize) is a typed error, never a panic.
        .map_err(http_err)
}

/// A redirect the policy did not follow reaches here as a plain 3xx
/// response (`Policy::none()` hands it back rather than erroring): refuse
/// it explicitly, so a redirect body is never taken for the artifact or its
/// metadata.
fn refuse_redirect(response: reqwest::Response) -> Result<reqwest::Response, UpdateError> {
    if response.status().is_redirection() {
        return Err(UpdateError::RedirectRefused);
    }
    Ok(response)
}

/// TLS enforcement for update URLs: `https` always; plaintext `http` only
/// for loopback (the test suite and dev rigs serve over 127.0.0.1).
pub(crate) fn ensure_tls_url(url: &str) -> Result<(), UpdateError> {
    let parsed = reqwest::Url::parse(url)
        .map_err(|error| UpdateError::Resolve(format!("invalid update url: {error}")))?;
    match parsed.scheme() {
        "https" => Ok(()),
        "http" if is_loopback_url(&parsed) => Ok(()),
        scheme => Err(UpdateError::InsecureUrl(format!(
            "scheme {scheme:?} (http is accepted only for loopback hosts)"
        ))),
    }
}

/// Loopback host check: `localhost` or any IP literal in loopback space.
pub(crate) fn is_loopback_url(url: &reqwest::Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<std::net::IpAddr>()
        .is_ok_and(|ip| ip.is_loopback())
}

/// Form the `extension` metadata URL for an artifact URL: the suffix is
/// appended to the PATH's last segment only, so the query (and fragment)
/// pass through byte-for-byte (`https://host/app?X-Amz-Signature=abc` →
/// `https://host/app.manifest?X-Amz-Signature=abc`). Trailing slashes are
/// trimmed first.
///
/// **Presigned-URL caveat, honestly:** query-preserving is NOT
/// signature-preserving for schemes that sign the PATH — SigV4 (S3), GCS
/// V4, and Azure SAS — so the metadata fetch answers 403 there, an ordinary
/// fails-closed update error. Such deployments serve manifests and
/// signatures at unsigned paths (they are public and self-authenticating)
/// or use a redirect flow (with the redirect host allowlisted).
pub(crate) fn metadata_url(artifact_url: &str, extension: &str) -> Result<String, UpdateError> {
    let mut url = reqwest::Url::parse(artifact_url).map_err(|error| {
        UpdateError::Resolve(format!("artifact url is not a valid URL: {error}"))
    })?;
    if url.cannot_be_a_base() {
        return Err(UpdateError::Resolve(format!(
            "artifact url scheme {:?} cannot carry a {extension} path",
            url.scheme()
        )));
    }
    let path = format!("{}{extension}", url.path().trim_end_matches('/'));
    url.set_path(&path);
    Ok(url.into())
}

/// Fetch a bounded metadata body under the METADATA timeout.
pub(crate) async fn fetch_metadata(
    url: &str,
    what: &str,
    limits: &Limits,
) -> Result<Vec<u8>, UpdateError> {
    ensure_tls_url(url)?;
    let response = refuse_redirect(
        http_client(limits, limits.metadata_timeout)?
            .get(url)
            .send()
            .await
            .map_err(http_err)?,
    )?
    .error_for_status()
    .map_err(http_err)?;
    if response
        .content_length()
        .is_some_and(|len| len > limits.max_metadata_bytes)
    {
        return Err(UpdateError::Resolve(format!(
            "{what} exceeds the {}-byte limit",
            limits.max_metadata_bytes
        )));
    }
    use futures_util::StreamExt as _;
    let mut stream = response.bytes_stream();
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(http_err)?;
        if body.len() as u64 + chunk.len() as u64 > limits.max_metadata_bytes {
            return Err(UpdateError::Resolve(format!(
                "{what} exceeds the {}-byte limit",
                limits.max_metadata_bytes
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Stream the artifact at `url` into `file` (the staged file's own
/// descriptor), bounded by the artifact cap — and, when the signed manifest
/// fixed it, by EXACTLY `expected_size` bytes: a `content-length` that
/// disagrees is refused before the body streams, the stream aborts at
/// `expected_size + 1`, and a short body fails. Answers the byte count.
pub(crate) async fn download_to(
    url: &str,
    file: &mut tokio::fs::File,
    limits: &Limits,
    expected_size: Option<u64>,
) -> Result<u64, UpdateError> {
    ensure_tls_url(url)?;
    let response = refuse_redirect(
        http_client(limits, limits.download_timeout)?
            .get(url)
            .send()
            .await
            .map_err(http_err)?,
    )?
    .error_for_status()
    .map_err(http_err)?;
    let content_length = response.content_length();
    if content_length.is_some_and(|len| len > limits.max_artifact_bytes) {
        return Err(UpdateError::ArtifactTooLarge {
            limit: limits.max_artifact_bytes,
        });
    }
    if let (Some(expected), Some(announced)) = (expected_size, content_length)
        && expected != announced
    {
        return Err(UpdateError::SizeMismatch {
            expected,
            actual: announced,
        });
    }

    use futures_util::StreamExt as _;
    use tokio::io::AsyncWriteExt as _;
    let mut downloaded = 0_u64;
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(http_err)?;
        downloaded += chunk.len() as u64;
        if downloaded > limits.max_artifact_bytes {
            return Err(UpdateError::ArtifactTooLarge {
                limit: limits.max_artifact_bytes,
            });
        }
        if let Some(expected) = expected_size
            && downloaded > expected
        {
            return Err(UpdateError::SizeMismatch {
                expected,
                actual: downloaded,
            });
        }
        file.write_all(&chunk).await?;
    }
    file.flush().await?;
    if let Some(expected) = expected_size
        && downloaded != expected
    {
        return Err(UpdateError::SizeMismatch {
            expected,
            actual: downloaded,
        });
    }
    Ok(downloaded)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> reqwest::Url {
        reqwest::Url::parse(s).unwrap()
    }

    /// Redirects are refused by default; the exact-host allowlist
    /// admits CDN hops, and the no-downgrade rule holds inside it.
    #[test]
    fn redirect_policy_matrix() {
        let origin = url("https://releases.example.com/app");
        let none: Vec<String> = Vec::new();
        let cdn = vec!["cdn.example.com".to_string(), "127.0.0.1".to_string()];
        // Default: nothing, not even another https host.
        assert!(!redirect_permitted(
            &none,
            std::slice::from_ref(&origin),
            &url("https://intranet.corp.example/admin")
        ));
        assert!(!redirect_permitted(
            &none,
            std::slice::from_ref(&origin),
            &url("https://cdn.example.com/app")
        ));
        // Allowlisted https host: yes (case-insensitive).
        assert!(redirect_permitted(
            &cdn,
            std::slice::from_ref(&origin),
            &url("https://CDN.example.com/app")
        ));
        // Not a suffix match.
        assert!(!redirect_permitted(
            &cdn,
            std::slice::from_ref(&origin),
            &url("https://evil-cdn.example.com/app")
        ));
        assert!(!redirect_permitted(
            &cdn,
            std::slice::from_ref(&origin),
            &url("https://cdn.example.com.evil.test/app")
        ));
        // An https chain never downgrades, even to an allowlisted loopback.
        assert!(!redirect_permitted(
            &cdn,
            std::slice::from_ref(&origin),
            &url("http://127.0.0.1:8080/app")
        ));
        // Plaintext loopback hops only inside all-loopback chains.
        let dev = url("http://127.0.0.1:9000/app");
        assert!(redirect_permitted(
            &cdn,
            std::slice::from_ref(&dev),
            &url("http://127.0.0.1:9001/app")
        ));
        assert!(!redirect_permitted(
            &cdn,
            std::slice::from_ref(&dev),
            &url("http://cdn.example.com/app")
        ));
    }

    #[test]
    fn tls_gate_allows_https_and_loopback_http_only() {
        assert!(ensure_tls_url("https://releases.example.com/app").is_ok());
        assert!(ensure_tls_url("http://127.0.0.1:8080/app").is_ok());
        assert!(ensure_tls_url("http://[::1]:8080/app").is_ok());
        assert!(ensure_tls_url("http://localhost/app").is_ok());
        assert!(matches!(
            ensure_tls_url("http://releases.example.com/app"),
            Err(UpdateError::InsecureUrl(_))
        ));
        assert!(matches!(
            ensure_tls_url("ftp://releases.example.com/app"),
            Err(UpdateError::InsecureUrl(_))
        ));
        assert!(matches!(
            ensure_tls_url("not a url"),
            Err(UpdateError::Resolve(_))
        ));
    }

    #[test]
    fn metadata_url_appends_to_the_path_preserving_the_query() {
        assert_eq!(
            metadata_url("https://releases.example.com/app/2.0.0/app", ".manifest").unwrap(),
            "https://releases.example.com/app/2.0.0/app.manifest"
        );
        assert_eq!(
            metadata_url(
                "https://bucket.storage.example.com/app?X-Amz-Signature=abc123",
                ".sha512"
            )
            .unwrap(),
            "https://bucket.storage.example.com/app.sha512?X-Amz-Signature=abc123"
        );
        assert_eq!(
            metadata_url("https://host/app/#frag", ".manifest").unwrap(),
            "https://host/app.manifest#frag"
        );
        assert!(matches!(
            metadata_url("not a url", ".manifest"),
            Err(UpdateError::Resolve(_))
        ));
        assert!(matches!(
            metadata_url("mailto:releases@example.com", ".manifest"),
            Err(UpdateError::Resolve(_))
        ));
    }

    #[test]
    fn limits_default_pins_the_documented_bounds() {
        let limits = Limits::default();
        assert_eq!(limits.max_artifact_bytes, 1024 * 1024 * 1024);
        assert_eq!(limits.max_metadata_bytes, 64 * 1024);
        assert_eq!(limits.connect_timeout, Duration::from_secs(15));
        assert_eq!(limits.download_timeout, Duration::from_secs(30 * 60));
        assert_eq!(limits.metadata_timeout, Duration::from_secs(60));
        assert!(limits.redirect_hosts.is_empty());
    }

    /// Code-assertion pin: every reqwest error site routes through
    /// `http_err` (URL-stripped) — the send/status/chunk sites and
    /// the client build, which answers a typed error instead of panicking.
    #[test]
    fn reqwest_error_sites_route_through_http_err() {
        let source = include_str!("net.rs");
        let body = source.split("#[cfg(test)]").next().unwrap();
        let sites = body.matches(".map_err(http_err)").count();
        assert_eq!(
            sites, 7,
            "every send/status/chunk site and the client build must strip the url"
        );
        assert!(!body.contains("map_err(UpdateError::Http)"));
    }

    // ---------------------------------------------------------------------
    // The bounds against a loopback server (the helper's fetches)

    use crate::tests_support::{Reply, stub};

    async fn fetch_package(
        url: &str,
        limits: &Limits,
        expected: Option<u64>,
    ) -> Result<Vec<u8>, UpdateError> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("package");
        let mut file = tokio::fs::File::create(&path).await.unwrap();
        download_to(url, &mut file, limits, expected).await?;
        drop(file);
        Ok(std::fs::read(&path).unwrap())
    }

    /// A redirect is followed only to an allowlisted host.
    #[tokio::test]
    async fn redirects_need_the_allowlist() {
        let cdn = stub(vec![("/cdn/pkg".into(), Reply::Ok(b"package".to_vec()))]);
        let origin = stub(vec![
            (
                "/pkg".into(),
                Reply::Redirect(format!("{}/cdn/pkg", cdn.base)),
            ),
            (
                "/pkg.manifest".into(),
                Reply::Redirect(format!("{}/cdn/pkg", cdn.base)),
            ),
        ]);
        let url = format!("{}/pkg", origin.base);
        let refused = fetch_package(&url, &Limits::default(), None)
            .await
            .unwrap_err();
        assert!(matches!(refused, UpdateError::RedirectRefused), "{refused}");
        let manifest = fetch_metadata(&format!("{url}.manifest"), "manifest", &Limits::default())
            .await
            .unwrap_err();
        assert!(
            matches!(manifest, UpdateError::RedirectRefused),
            "{manifest}"
        );
        assert!(
            cdn.requests().is_empty(),
            "the redirect must not be followed"
        );
        let allowed = Limits {
            redirect_hosts: Arc::from(vec!["127.0.0.1".to_owned()]),
            ..Limits::default()
        };
        assert_eq!(
            fetch_package(&url, &allowed, Some(7)).await.unwrap(),
            b"package"
        );
        assert_eq!(cdn.requests(), vec!["/cdn/pkg".to_owned()]);
    }

    #[tokio::test]
    async fn sizes_are_capped_and_must_be_exact() {
        let body = vec![7_u8; 4096];
        let server = stub(vec![
            ("/pkg".into(), Reply::Ok(body.clone())),
            (
                "/short".into(),
                Reply::Truncated(body.len(), body[..100].to_vec()),
            ),
            ("/meta".into(), Reply::Ok(vec![b'x'; 70 * 1024])),
        ]);
        let small = Limits {
            max_artifact_bytes: 100,
            ..Limits::default()
        };
        let url = format!("{}/pkg", server.base);
        assert!(matches!(
            fetch_package(&url, &small, None).await,
            Err(UpdateError::ArtifactTooLarge { limit: 100 })
        ));
        // The manifest's size disagrees with the announced length, or the
        // body ends short of it.
        assert!(matches!(
            fetch_package(&url, &Limits::default(), Some(4095)).await,
            Err(UpdateError::SizeMismatch {
                expected: 4095,
                actual: 4096
            })
        ));
        assert!(
            fetch_package(
                &format!("{}/short", server.base),
                &Limits::default(),
                Some(4096)
            )
            .await
            .is_err()
        );
        assert_eq!(
            fetch_package(&url, &Limits::default(), Some(4096))
                .await
                .unwrap(),
            body
        );
        // A metadata body past its cap.
        let error = fetch_metadata(
            &format!("{}/meta", server.base),
            "manifest",
            &Limits::default(),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(&error, UpdateError::Resolve(m) if m.contains("65536-byte limit")),
            "{error}"
        );
    }

    /// Each cap holds on its own. A length header past a cap is refused
    /// before the body is read; without a length header, the stream is cut
    /// at the cap, and nothing past the manifest's size reaches the disk.
    #[tokio::test]
    async fn each_cap_holds_without_the_length_header_and_before_the_body() {
        let big = vec![b'x'; 8 * 1024 * 1024];
        let server = stub(vec![
            (
                "/meta-streamed".into(),
                Reply::Unannounced(vec![b'x'; 70 * 1024]),
            ),
            (
                "/meta-announced".into(),
                Reply::Truncated(70 * 1024, b"short".to_vec()),
            ),
            ("/pkg-streamed".into(), Reply::Unannounced(big.clone())),
            (
                "/pkg-announced".into(),
                Reply::Truncated(big.len(), b"short".to_vec()),
            ),
        ]);
        let over_limit = |error: &UpdateError| matches!(error, UpdateError::Resolve(m) if m.contains("65536-byte limit"));
        // Metadata: cut mid-stream, and refused on the header alone (the
        // body ends short of the header, so reading it would be an http
        // error instead).
        for path in ["/meta-streamed", "/meta-announced"] {
            let error = fetch_metadata(
                &format!("{}{path}", server.base),
                "manifest",
                &Limits::default(),
            )
            .await
            .unwrap_err();
            assert!(over_limit(&error), "{path}: {error}");
        }
        // The artifact cap, both ways.
        let small = Limits {
            max_artifact_bytes: 100,
            ..Limits::default()
        };
        for path in ["/pkg-streamed", "/pkg-announced"] {
            let error = fetch_package(&format!("{}{path}", server.base), &small, None)
                .await
                .unwrap_err();
            assert!(
                matches!(error, UpdateError::ArtifactTooLarge { limit: 100 }),
                "{path}: {error}"
            );
        }
        // The manifest's size, streamed: refused at the first chunk past
        // it, before that chunk is written.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("package");
        let mut file = tokio::fs::File::create(&path).await.unwrap();
        let error = download_to(
            &format!("{}/pkg-streamed", server.base),
            &mut file,
            &Limits::default(),
            Some(100),
        )
        .await
        .unwrap_err();
        drop(file);
        assert!(
            matches!(error, UpdateError::SizeMismatch { expected: 100, .. }),
            "{error}"
        );
        assert!(
            std::fs::metadata(&path).unwrap().len() <= 100,
            "bytes past the manifest's size reached the disk"
        );
    }

    /// Metadata fetches run on their own short budget, independent
    /// of the package download's.
    #[tokio::test]
    async fn metadata_and_downloads_have_their_own_timeouts() {
        let server = stub(vec![(
            "/slow".into(),
            Reply::Slow(Duration::from_secs(3), b"x".to_vec()),
        )]);
        let url = format!("{}/slow", server.base);
        let metadata = Limits {
            download_timeout: Duration::from_secs(60),
            metadata_timeout: Duration::from_millis(200),
            ..Limits::default()
        };
        let started = std::time::Instant::now();
        let error = fetch_metadata(&url, "manifest", &metadata)
            .await
            .unwrap_err();
        assert!(
            matches!(&error, UpdateError::Http(e) if e.is_timeout()),
            "{error}"
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        let download = Limits {
            download_timeout: Duration::from_millis(200),
            ..Limits::default()
        };
        let error = fetch_package(&url, &download, None).await.unwrap_err();
        assert!(
            matches!(&error, UpdateError::Http(e) if e.is_timeout()),
            "{error}"
        );
    }

    /// An HTTP error never carries the URL: it may be a presigned GET with
    /// credentials in its query.
    #[tokio::test]
    async fn http_errors_never_carry_url_query_material() {
        let token = "TOP-SECRET-QUERY-TOKEN-9f3c";
        for url in [
            format!("http://127.0.0.1:1/pkg?access-token={token}"),
            format!("{}/missing?access-token={token}", stub(Vec::new()).base),
        ] {
            let error = fetch_package(&url, &Limits::default(), None)
                .await
                .unwrap_err();
            let manifest = fetch_metadata(&url, "manifest", &Limits::default())
                .await
                .unwrap_err();
            for rendered in [error.to_string(), manifest.to_string()] {
                for forbidden in [token, "access-token", "http://"] {
                    assert!(!rendered.contains(forbidden), "{rendered}");
                }
            }
        }
    }
}
