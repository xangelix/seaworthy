//! The lab's error type.

/// What went wrong in the lab: every error names its cause for the lane's
/// log.
#[derive(Debug, thiserror::Error)]
pub enum LabError {
    /// File or socket i/o failed (`what` names the file or address).
    #[error("{what}: {source}")]
    Io {
        /// The file or address.
        what: String,
        /// The error.
        source: std::io::Error,
    },
    /// An argument or input file is invalid.
    #[error("{0}")]
    Invalid(String),
    /// A cryptographic operation failed (key generation, signing).
    #[error("crypto: {0}")]
    Crypto(String),
    /// The TLS configuration couldn't be built.
    #[error("tls: {0}")]
    Tls(String),
    /// The required-version endpoint couldn't be reached, or answered
    /// something other than one version token.
    #[error("required version: {0}")]
    Fetch(String),
}

impl LabError {
    /// An i/o error on `what`.
    #[cfg_attr(
        not(any(feature = "server", feature = "ca")),
        allow(dead_code, reason = "used by the server and the CA only")
    )]
    pub(crate) fn io(what: impl std::fmt::Display, source: std::io::Error) -> Self {
        Self::Io {
            what: what.to_string(),
            source,
        }
    }
}
