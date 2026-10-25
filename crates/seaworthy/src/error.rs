//! The one error type.

use std::path::{Path, PathBuf};

/// Why `seaworthy` refused or failed.
#[derive(Debug, thiserror::Error)]
pub enum DistError {
    /// A file couldn't be read or written.
    #[error("{path}: {source}")]
    Io {
        /// The file.
        path: PathBuf,
        /// The OS error.
        source: std::io::Error,
    },
    /// `seaworthy.toml` is invalid: the message names the key.
    #[error("seaworthy.toml: {0}")]
    Config(String),
    /// The artifacts failed `verify`: every finding.
    #[error("verify found {} problem(s):\n  - {}", .0.len(), .0.join("\n  - "))]
    Verify(Vec<String>),
    /// Laying out a tree failed.
    #[error("layout: {0}")]
    Layout(String),
    /// An external tool is missing or failed.
    #[error("{0}")]
    Tool(String),
    /// Signing was refused or failed: a policy gap, a key the product's
    /// clients would refuse, a failing signer.
    #[error("signing: {0}")]
    Sign(String),
    /// A CI configuration couldn't be read (the release-ordering lint).
    #[error("CI configuration: {0}")]
    Ci(String),
    /// The release-ordering lint's findings: a server could deploy before
    /// a client it serves is published.
    #[error("release order: {} problem(s):\n  - {}", .0.len(), .0.join("\n  - "))]
    Order(Vec<String>),
    /// A release version or sequence was refused.
    #[error(transparent)]
    Version(#[from] crate::version::VersionError),
}

impl DistError {
    /// An I/O error on `path`.
    pub fn io(path: &Path, source: std::io::Error) -> Self {
        Self::Io {
            path: path.to_path_buf(),
            source,
        }
    }
}
