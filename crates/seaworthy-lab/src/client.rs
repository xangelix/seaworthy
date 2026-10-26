//! The required-version client: what a fixture's update helper asks for
//! the version token to install (its version source, a caller closure:
//! `seaworthy_updater::helper::HelperConfig::new`).
//!
//! It is built as the update helper builds its downloads: TLS from
//! seaworthy-crypto's client builder with the operating system's trust
//! store attached (the platform verifier: where the TLS lanes install
//! their throwaway CA), no proxy, no redirects, a connect timeout and an
//! overall budget. The URL is `https`, or `http` to a loopback address
//! (the conformance lanes), without credentials or a fragment. The answer
//! must be `200` with a body of at most [`MAX_TOKEN_BYTES`] holding one
//! version token (surrounding whitespace ignored), which the helper checks
//! again against the signed manifest it then fetches.

use std::time::Duration;

use reqwest::Url;

use crate::{LabError, MAX_TOKEN_BYTES};

/// The longest a connection attempt may take, within the budget.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// A client for one required-version endpoint.
#[derive(Clone, Debug)]
pub struct RequiredVersionClient {
    url: Url,
    client: reqwest::Client,
}

impl RequiredVersionClient {
    /// A client for `url`, each request bounded by `budget` (connect,
    /// request and body), on the platform's trust store.
    ///
    /// # Errors
    /// [`LabError::Invalid`] for a URL that isn't `https` (or `http` to a
    /// loopback address), or carries credentials or a fragment;
    /// [`LabError::Tls`] when the TLS configuration (the platform verifier)
    /// can't be built.
    pub fn new(url: &str, budget: Duration) -> Result<Self, LabError> {
        use rustls_platform_verifier::BuilderVerifierExt as _;
        let url = check_url(url)?;
        // seaworthy-crypto's provider and policy; the OS trust store.
        let tls = seaworthy_crypto::tls::client_config_builder()
            .and_then(|builder| builder.with_platform_verifier())
            .map_err(|e| LabError::Tls(e.to_string()))?
            .with_no_client_auth();
        Self::with_tls(url, tls, budget)
    }

    /// A client for `url` on the TLS configuration `tls`.
    fn with_tls(url: Url, tls: rustls::ClientConfig, budget: Duration) -> Result<Self, LabError> {
        let client = reqwest::Client::builder()
            .use_preconfigured_tls(tls)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT.min(budget))
            .timeout(budget)
            .build()
            .map_err(|e| LabError::Tls(e.without_url().to_string()))?;
        Ok(Self { url, client })
    }

    /// The URL asked.
    #[must_use]
    pub fn url(&self) -> &str {
        self.url.as_str()
    }

    /// The version token the endpoint names.
    ///
    /// # Errors
    /// [`LabError::Fetch`] when the endpoint can't be reached in time,
    /// answers anything but `200`, or a body that isn't one version token
    /// of at most [`MAX_TOKEN_BYTES`].
    pub async fn fetch(&self) -> Result<String, LabError> {
        let fetch = |e: reqwest::Error| LabError::Fetch(e.without_url().to_string());
        let mut response = self
            .client
            .get(self.url.clone())
            .send()
            .await
            .map_err(fetch)?;
        let status = response.status();
        if status != reqwest::StatusCode::OK {
            return Err(LabError::Fetch(format!("the endpoint answered {status}")));
        }
        let limit = u64::try_from(MAX_TOKEN_BYTES).unwrap_or(u64::MAX);
        if response
            .content_length()
            .is_some_and(|length| length > limit)
        {
            return Err(LabError::Fetch(format!(
                "the answer is longer than {MAX_TOKEN_BYTES} bytes"
            )));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(fetch)? {
            if body.len().saturating_add(chunk.len()) > MAX_TOKEN_BYTES {
                return Err(LabError::Fetch(format!(
                    "the answer is longer than {MAX_TOKEN_BYTES} bytes"
                )));
            }
            body.extend_from_slice(&chunk);
        }
        let text = String::from_utf8(body)
            .map_err(|_| LabError::Fetch("the answer isn't UTF-8".to_owned()))?;
        let token = text.trim();
        seaworthy_formats::validate_version(token)
            .map_err(|e| LabError::Fetch(format!("the answer isn't a version token: {e}")))?;
        Ok(token.to_owned())
    }
}

/// `https`, or `http` to a loopback address; no credentials or fragment.
fn check_url(url: &str) -> Result<Url, LabError> {
    let parsed = Url::parse(url).map_err(|e| LabError::Invalid(format!("the URL: {e}")))?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(LabError::Invalid(
            "the URL must not carry credentials".to_owned(),
        ));
    }
    if parsed.fragment().is_some() {
        return Err(LabError::Invalid(
            "the URL must not carry a fragment".to_owned(),
        ));
    }
    let loopback = parsed
        .host_str()
        .map(|host| host.trim_start_matches('[').trim_end_matches(']'))
        .and_then(|host| host.parse::<std::net::IpAddr>().ok())
        .is_some_and(|ip| ip.is_loopback());
    match parsed.scheme() {
        "https" if parsed.host().is_some() => Ok(parsed),
        "http" if loopback => Ok(parsed),
        _ => Err(LabError::Invalid(
            "the URL must be https, or http to a loopback address".to_owned(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls_are_checked() {
        for good in [
            "https://updates.lab.invalid/_lab/required-version",
            "http://127.0.0.1:8470/_lab/required-version",
            "http://[::1]:8470/_lab/required-version",
        ] {
            assert!(check_url(good).is_ok(), "{good}");
        }
        for bad in [
            "http://updates.lab.invalid/_lab/required-version",
            "http://localhost:8470/x",
            "http://10.0.0.1/x",
            "https://user:pw@updates.lab.invalid/x",
            "https://updates.lab.invalid/x#frag",
            "ftp://127.0.0.1/x",
            "not a url",
        ] {
            assert!(check_url(bad).is_err(), "{bad}");
        }
    }

    #[cfg(all(feature = "server", feature = "ca"))]
    mod against_the_server {
        use std::net::SocketAddr;
        use std::path::Path;

        use rustls::pki_types::CertificateDer;
        use rustls::pki_types::pem::PemObject as _;

        use super::*;
        use crate::ca::{DEFAULT_VALIDITY, LabCa};
        use crate::server::{Options, Server, TlsFiles, Token};

        const BUDGET: Duration = Duration::from_secs(20);

        fn serve(root: &Path, token: Token, tls: Option<TlsFiles>) -> SocketAddr {
            let server = Server::bind(Options {
                root: root.to_owned(),
                token,
                listen: vec!["127.0.0.1:0".to_owned()],
                hold: None,
                tls,
                ready: None,
            })
            .unwrap();
            server.spawn().unwrap()[0]
        }

        /// A client trusting `ca` alone, with `host` resolved to `addr`.
        fn client(ca: &LabCa, host: &str, addr: SocketAddr) -> RequiredVersionClient {
            let mut roots = rustls::RootCertStore::empty();
            roots
                .add(CertificateDer::from_pem_slice(ca.ca_pem().as_bytes()).unwrap())
                .unwrap();
            let tls = seaworthy_crypto::tls::client_config_builder()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
            let url = Url::parse(&format!(
                "https://{host}:{}/_lab/required-version",
                addr.port()
            ))
            .unwrap();
            let client = reqwest::Client::builder()
                .use_preconfigured_tls(tls)
                .no_proxy()
                .resolve(host, addr)
                .redirect(reqwest::redirect::Policy::none())
                .timeout(BUDGET)
                .build()
                .unwrap();
            RequiredVersionClient { url, client }
        }

        #[tokio::test]
        async fn plain_http_on_loopback() {
            let dir = tempfile::tempdir().unwrap();
            let addr = serve(dir.path(), Token::Fixed("1.4.0+abc".to_owned()), None);
            let client =
                RequiredVersionClient::new(&format!("http://{addr}/_lab/required-version"), BUDGET)
                    .unwrap();
            assert_eq!(client.fetch().await.unwrap(), "1.4.0+abc");

            // A path that isn't the endpoint: 404, an error.
            let missing =
                RequiredVersionClient::new(&format!("http://{addr}/missing"), BUDGET).unwrap();
            assert!(matches!(missing.fetch().await, Err(LabError::Fetch(_))));

            // An answer that isn't a version token.
            std::fs::write(dir.path().join("big"), "x".repeat(MAX_TOKEN_BYTES + 1)).unwrap();
            std::fs::write(dir.path().join("bad"), "not a token").unwrap();
            for name in ["big", "bad"] {
                let client =
                    RequiredVersionClient::new(&format!("http://{addr}/{name}"), BUDGET).unwrap();
                assert!(
                    matches!(client.fetch().await, Err(LabError::Fetch(_))),
                    "{name}"
                );
            }
        }

        #[tokio::test]
        async fn tls_with_the_lab_ca() {
            let dir = tempfile::tempdir().unwrap();
            let names = vec![
                "packages.lab.invalid".to_owned(),
                "updates.lab.invalid".to_owned(),
            ];
            let ca = LabCa::generate(&names, DEFAULT_VALIDITY).unwrap();
            let tls = dir.path().join("tls");
            ca.write(&tls).unwrap();
            let root = dir.path().join("root");
            std::fs::create_dir_all(&root).unwrap();
            let addr = serve(
                &root,
                Token::Fixed("2.0.0+lab".to_owned()),
                Some(TlsFiles {
                    cert: tls.join("leaf.pem"),
                    key: tls.join("leaf.key"),
                }),
            );
            for host in &names {
                assert_eq!(
                    client(&ca, host, addr).fetch().await.unwrap(),
                    "2.0.0+lab",
                    "{host}"
                );
            }
            // A name the leaf doesn't carry: refused by the verifier.
            assert!(
                client(&ca, "other.lab.invalid", addr)
                    .fetch()
                    .await
                    .is_err(),
                "a name outside the certificate"
            );
            // Another lab's root doesn't vouch for this one's leaf.
            let other = LabCa::generate(&names, DEFAULT_VALIDITY).unwrap();
            assert!(client(&other, &names[0], addr).fetch().await.is_err());
        }
    }
}
