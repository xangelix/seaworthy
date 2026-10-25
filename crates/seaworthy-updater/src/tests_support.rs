//! Test support shared by the crate's tests: the switch that makes a
//! missing package tool a failure, and (with the helper) a loopback HTTP
//! stub with path-routed canned responses and a request log, and release
//! signing keys.

/// `SEAWORTHY_REQUIRE_PACKAGE_TOOLS=1`: a test needing a real tool (gpg,
/// rpmkeys, pacman-conf) fails instead of skipping when it's missing (CI
/// sets it, with every tool installed; the seaworthy CLI's tests read the
/// same switch).
#[cfg(unix)]
pub(crate) fn tools_required() -> bool {
    // allow-std-env: test-only switch, the seaworthy CLI's tests read the same one
    std::env::var_os("SEAWORTHY_REQUIRE_PACKAGE_TOOLS").is_some_and(|v| v == "1")
}

/// Writes an executable test script (mode 0755) at `path` through a child
/// process, so this process never holds the file open for writing. Tests
/// run on parallel threads: a script still open for writing in a forked,
/// not yet exec'd child of another thread fails to run with `ETXTBSY`
/// ("Text file busy").
#[cfg(unix)]
pub(crate) fn write_script(path: &std::path::Path, contents: &str) {
    use std::io::Write as _;
    let mut child = std::process::Command::new("/bin/sh")
        .args(["-c", "cat > \"$1\" && chmod 755 \"$1\"", "sh"])
        .arg(path)
        .stdin(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(contents.as_bytes())
        .unwrap();
    assert!(
        child.wait().unwrap().success(),
        "writing {}",
        path.display()
    );
}

#[cfg(all(feature = "helper", unix))]
pub(crate) use http::Stub;
#[cfg(feature = "helper")]
pub(crate) use http::{Reply, stub};
#[cfg(all(feature = "helper", unix))]
pub(crate) use keys::{SigningKey, signed};

/// Loopback HTTP stub: path-routed canned responses, request log, no
/// dev-dependencies.
#[cfg(feature = "helper")]
mod http {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    #[derive(Clone)]
    pub(crate) enum Reply {
        /// 200 with a body.
        Ok(Vec<u8>),
        /// Any status line with a body.
        Status(&'static str, Vec<u8>),
        /// 302 to a location.
        Redirect(String),
        /// Wait, then 200.
        Slow(Duration, Vec<u8>),
        /// Announce a length, deliver `body`, close.
        Truncated(usize, Vec<u8>),
        /// 200 with no length header: the body ends when the connection closes.
        Unannounced(Vec<u8>),
    }

    pub(crate) struct Stub {
        pub(crate) base: String,
        requests: Arc<Mutex<Vec<String>>>,
    }

    impl Stub {
        pub(crate) fn requests(&self) -> Vec<String> {
            self.requests.lock().unwrap().clone()
        }
    }

    fn drain_request(stream: &mut std::net::TcpStream) -> String {
        use std::io::Read as _;
        let mut request = Vec::new();
        let mut buf = [0_u8; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            match stream.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(read) => request.extend_from_slice(&buf[..read]),
            }
        }
        String::from_utf8_lossy(&request)
            .split_whitespace()
            .nth(1)
            .unwrap_or_default()
            .to_string()
    }

    fn write_reply(stream: &mut std::net::TcpStream, reply: &Reply) {
        use std::io::Write as _;
        let (status, headers, body): (&str, String, &[u8]) = match reply {
            Reply::Ok(body) => (
                "200 OK",
                format!("content-length: {}\r\n", body.len()),
                body,
            ),
            Reply::Status(status, body) => {
                (status, format!("content-length: {}\r\n", body.len()), body)
            }
            Reply::Redirect(location) => (
                "302 Found",
                format!("location: {location}\r\ncontent-length: 0\r\n"),
                &[],
            ),
            Reply::Slow(delay, body) => {
                std::thread::sleep(*delay);
                (
                    "200 OK",
                    format!("content-length: {}\r\n", body.len()),
                    body,
                )
            }
            Reply::Truncated(announced, body) => {
                ("200 OK", format!("content-length: {announced}\r\n"), body)
            }
            Reply::Unannounced(body) => ("200 OK", String::new(), body),
        };
        let head = format!("HTTP/1.1 {status}\r\n{headers}connection: close\r\n\r\n");
        let _ = stream.write_all(head.as_bytes());
        let _ = stream.write_all(body);
        let _ = stream.flush();
    }

    /// Serve `routes` (request path, query stripped → reply) forever on a
    /// leaked thread; unknown paths answer 404. Every request path is logged.
    pub(crate) fn stub(routes: Vec<(String, Reply)>) -> Stub {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&requests);
        let routes: std::collections::HashMap<String, Reply> = routes.into_iter().collect();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let routes = routes.clone();
                let log = Arc::clone(&log);
                std::thread::spawn(move || {
                    let target = drain_request(&mut stream);
                    log.lock().unwrap().push(target.clone());
                    let path = target.split('?').next().unwrap_or_default().to_string();
                    let reply = routes
                        .get(&path)
                        .cloned()
                        .unwrap_or(Reply::Status("404 Not Found", b"nope".to_vec()));
                    write_reply(&mut stream, &reply);
                });
            }
        });
        Stub { base, requests }
    }
}

/// Release signing keys (the release-side operation, in-process), as
/// seaworthy-formats' own tests sign. The helper's flow tests run on unix.
#[cfg(all(feature = "helper", unix))]
mod keys {
    use crate::{
        ManifestSignature, ReleaseKey, ReleaseManifest, SignatureAlgorithm, release_key_id,
    };

    pub(crate) enum SigningKey {
        MlDsa87(seaworthy_crypto::mldsa::SigningKey),
        EcdsaP256(seaworthy_crypto::ecdsa::SigningKey),
        Ed25519(seaworthy_crypto::ed25519::SigningKey),
    }

    impl SigningKey {
        pub(crate) fn generate(algorithm: SignatureAlgorithm) -> Self {
            match algorithm {
                SignatureAlgorithm::MlDsa87 => {
                    let mut seed = [0u8; 32];
                    seaworthy_crypto::rand::fill(&mut seed).unwrap();
                    Self::MlDsa87(seaworthy_crypto::mldsa::SigningKey::from_seed(&seed).unwrap())
                }
                SignatureAlgorithm::EcdsaP256 => Self::EcdsaP256(
                    seaworthy_crypto::ecdsa::SigningKey::generate_pkcs8()
                        .unwrap()
                        .0,
                ),
                SignatureAlgorithm::Ed25519 => Self::Ed25519(
                    seaworthy_crypto::ed25519::SigningKey::generate_pkcs8()
                        .unwrap()
                        .0,
                ),
            }
        }

        fn algorithm(&self) -> SignatureAlgorithm {
            match self {
                Self::MlDsa87(_) => SignatureAlgorithm::MlDsa87,
                Self::EcdsaP256(_) => SignatureAlgorithm::EcdsaP256,
                Self::Ed25519(_) => SignatureAlgorithm::Ed25519,
            }
        }

        fn public_key(&self) -> Vec<u8> {
            match self {
                Self::MlDsa87(key) => key.public_key().to_vec(),
                Self::EcdsaP256(key) => key.public_key_der(),
                Self::Ed25519(key) => key.public_key().to_vec(),
            }
        }

        pub(crate) fn release_key(&self) -> ReleaseKey {
            ReleaseKey::new(self.public_key(), self.algorithm()).unwrap()
        }

        fn sign(&self, statement: &[u8]) -> ManifestSignature {
            let signature = match self {
                Self::MlDsa87(key) => key.sign(statement).to_vec(),
                Self::EcdsaP256(key) => key.sign(statement).unwrap(),
                Self::Ed25519(key) => key.sign(statement).to_vec(),
            };
            ManifestSignature {
                algorithm: self.algorithm(),
                key_id: release_key_id(self.algorithm(), &self.public_key()),
                signature,
            }
        }
    }

    /// `manifest` signed by every key in `keys`.
    pub(crate) fn signed(manifest: &ReleaseManifest, keys: &[&SigningKey]) -> Vec<u8> {
        let statement = manifest.statement().unwrap();
        let signatures: Vec<_> = keys.iter().map(|key| key.sign(&statement)).collect();
        manifest.encode_signed(&signatures).unwrap()
    }
}
