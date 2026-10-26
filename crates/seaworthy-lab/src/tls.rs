//! The lab server's TLS configuration: the one rustls server configuration
//! in the repository outside seaworthy-crypto (an allowlisted site in
//! `scripts/tls-construction-allowlist.txt`).
//!
//! seaworthy ships no TLS server, so seaworthy-crypto has no server
//! builder; the lab's is built here on seaworthy-crypto's provider (its
//! key-exchange groups, cipher suites and FIPS filtering) and protocol
//! versions, so the lab negotiates only what the TLS policy permits, the
//! same policy the update helper's client offers. Nothing else is
//! configured: no client authentication, one certificate chain, ALPN
//! `http/1.1`.

use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::LabError;

/// The server configuration for the chain in `cert` and the key in `key`
/// (PEM files, as [`crate::ca::LabCa::write`] writes them).
pub(crate) fn server_config(
    cert: &Path,
    key: &Path,
) -> Result<Arc<rustls::ServerConfig>, LabError> {
    let chain = CertificateDer::pem_file_iter(cert)
        .and_then(|certs| certs.collect::<Result<Vec<_>, _>>())
        .map_err(|e| LabError::Tls(format!("{}: {e}", cert.display())))?;
    if chain.is_empty() {
        return Err(LabError::Tls(format!("{}: no certificate", cert.display())));
    }
    let key = PrivateKeyDer::from_pem_file(key)
        .map_err(|e| LabError::Tls(format!("{}: {e}", key.display())))?;
    let mut config = rustls::ServerConfig::builder_with_provider(seaworthy_crypto::tls_provider())
        .with_protocol_versions(seaworthy_crypto::tls::protocol_versions())
        .map_err(|e| LabError::Tls(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| LabError::Tls(e.to_string()))?;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}
