//! The one error: what couldn't be trusted, and why.

#![forbid(unsafe_code)]

/// Why an object can't be trusted, or why what the decision needs couldn't
/// be read (which counts the same: an audit fails closed). The message names
/// the object and the reason, ready for a log line or a caller's own error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct Error {
    message: String,
}

impl Error {
    /// An error with `message`.
    #[cfg_attr(
        not(any(unix, windows)),
        allow(dead_code, reason = "only the platform audits fail")
    )]
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    /// The message: the object and why.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl From<Error> for String {
    fn from(error: Error) -> Self {
        error.message
    }
}
