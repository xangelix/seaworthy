//! The outcome taxonomy every phase of the service-main state machine
//! speaks.
//!
//! Init and the service body don't return plain `Result`s to
//! [`crate::run_service`]; they return an [`Outcome`], so the state machine
//! can tell "stop cleanly" apart from "die dirty so the supervisor restarts
//! us". A version rejection from the caller's server is neither: a service
//! asks the update helper (seaworthy-updater's request API) and keeps
//! going, and the package manager restarts it once the new release is
//! installed.

// ---------------------------------------------------------------------------

/// How a service phase (init or body) ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome<T, E> {
    /// Phase completed; for init, carries the value handed to the body.
    Success(T),
    /// Unrecoverable for this process lifetime; the supervisor should
    /// restart us (or give up, per the [`crate::FailurePolicy`]).
    Fatal(E),
}

impl<T, E> Outcome<T, E> {
    /// Map the success value, leaving `Fatal` untouched.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Outcome<U, E> {
        match self {
            Self::Success(value) => Outcome::Success(f(value)),
            Self::Fatal(e) => Outcome::Fatal(e),
        }
    }
}

impl<T, E> From<Result<T, E>> for Outcome<T, E> {
    /// `Ok` is [`Outcome::Success`], `Err` is [`Outcome::Fatal`].
    fn from(result: Result<T, E>) -> Self {
        match result {
            Ok(value) => Self::Success(value),
            Err(error) => Self::Fatal(error),
        }
    }
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn results_map_onto_outcomes() {
        assert_eq!(
            Outcome::<u32, &str>::from(Ok(42)).map(|v| v + 1),
            Outcome::Success(43)
        );
        assert_eq!(
            Outcome::<u32, &str>::from(Err("boom")).map(|v| v + 1),
            Outcome::Fatal("boom")
        );
    }
}
