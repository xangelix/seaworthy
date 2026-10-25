//! Image pulls that absorb registry hiccups BEFORE a test body runs.
//!
//! **Why.** Pulling a digest-pinned image on demand (testcontainers pulls
//! when the container create answers 404) happens exactly once, with no
//! retry. A burst of container tests on a cold daemon then trips the
//! registries' anonymous rate limits (Docker Hub, public.ecr.aws,
//! ghcr.io): the start panics, the runner retries, the retry passes, and a
//! fail-if-flaky CI profile (rightly) turns the pass-on-retry into a red
//! run. The test was never flaky; the infrastructure step was.
//!
//! **What.** [`ensure_image`] runs in the one launch path
//! ([`crate::launch`]) before every container start, and in the pre-pull
//! step (`scripts/pull-test-images.sh` → [`crate::prepull`]):
//!
//! 1. the reference must be a digest pin ([`crate::images::validate_pin`]),
//!    or it is refused before the daemon is asked anything;
//! 2. the daemon is asked whether it already holds the image (the
//!    `docker image inspect` call, by digest): present means done, with no
//!    registry traffic at all;
//! 3. otherwise testcontainers' own pull runs — the same daemon, the same
//!    credentials (`DOCKER_AUTH_CONFIG`, `DOCKER_CONFIG`,
//!    `~/.docker/config.json`) and platform it would have used on demand —
//!    and a TRANSIENT registry failure is retried with bounded, jittered
//!    exponential backoff ([`PULL_RETRY_INITIAL_DELAY`] doubling to
//!    [`PULL_RETRY_MAX_DELAY`], within [`PULL_RETRY_BUDGET`]), each retry
//!    logged with its cause.
//!
//! **What is retried** — only a failure the DAEMON reported about its
//! registry round-trip (a bollard `DockerResponseServerError` or
//! `DockerStreamError` inside testcontainers' pull error), and only when it
//! reads as: a rate limit (HTTP 429, `toomanyrequests`, "rate exceeded"), a
//! registry 5xx, a connection reset or refused, a TLS-handshake or request
//! timeout, or an unexpected EOF mid-download ([`TransientCause`]).
//!
//! **What is never retried** — authentication and authorization failures,
//! a manifest that is unknown or missing (for this platform), a digest or
//! content-verification failure, anything the rules do not recognize
//! (an offline machine's DNS failure included: it fails at once instead of
//! waiting out the budget), any failure talking to the daemon itself, and
//! everything after the pull: create, start, readiness, and port collisions
//! stay in [`crate::launch`], because the retry wraps the pull call and
//! nothing else.
//!
//! **Pins are never weakened.** Every attempt asks for the exact same
//! `name:tag@sha256:…` reference, the daemon verifies the content against
//! the digest, and a mismatch is permanent. There is no tag-only fallback.
//!
//! **Fail-if-flaky stays.** The retries happen before the test body runs and
//! never surface to the test runner, so a genuinely flaky test still fails
//! the run.

use std::{fmt, time::Duration};

use testcontainers::{
    GenericImage, TestcontainersError, core::error::ClientError, runners::AsyncRunner as _,
};

use crate::{images, split_image};

// ---------------------------------------------------------------------------
// The policy
// ---------------------------------------------------------------------------

/// The wait after the first failed attempt (nominal: jitter only shortens it).
pub const PULL_RETRY_INITIAL_DELAY: Duration = Duration::from_secs(2);

/// The longest single wait: the doubling stops here. Long enough for a
/// per-minute registry window to reopen, short enough to notice recovery.
pub const PULL_RETRY_MAX_DELAY: Duration = Duration::from_secs(30);

/// The total retry budget, measured from the first attempt: no retry starts
/// when waiting for it would cross this line. The nominal schedule — 2, 4,
/// 8, 16, then 30 s five times — spends exactly this in nine waits (ten
/// attempts). It stays well inside a test runner's kill timeout for
/// container suites (10 min is usual) while outlasting a burst limit.
pub const PULL_RETRY_BUDGET: Duration = Duration::from_secs(180);

/// Equal jitter: each wait is uniform in `[nominal·(1 − J), nominal]`:
/// never later than the schedule, and parallel test processes (or CI jobs
/// sharing one egress address) no longer retry in lockstep.
pub const PULL_RETRY_JITTER: f64 = 0.5;

/// The nominal (pre-jitter) wait after `failed` failed attempts, 1-based:
/// [`PULL_RETRY_INITIAL_DELAY`] · 2^(failed − 1), capped at
/// [`PULL_RETRY_MAX_DELAY`].
#[must_use]
pub fn nominal_wait(failed: u32) -> Duration {
    let shift = failed.saturating_sub(1).min(16);
    PULL_RETRY_INITIAL_DELAY
        .saturating_mul(1_u32 << shift)
        .min(PULL_RETRY_MAX_DELAY)
}

/// Apply [`PULL_RETRY_JITTER`] for a draw `rand01` in `[0, 1]` (clamped; a
/// NaN reads as the midpoint).
fn jittered(wait: Duration, rand01: f64) -> Duration {
    let rand01 = if rand01.is_nan() {
        0.5
    } else {
        rand01.clamp(0.0, 1.0)
    };
    wait.mul_f64((1.0 - PULL_RETRY_JITTER) + PULL_RETRY_JITTER * rand01)
}

/// A draw in `[0, 1]` from the workspace CSPRNG (`seaworthy_crypto::rand`,
/// the one randomness entry point). A failed draw degrades to the
/// midpoint: a correct wait without jitter, never a failure.
fn rand01() -> f64 {
    let mut bytes = [0_u8; 8];
    if seaworthy_crypto::rand::fill(&mut bytes).is_err() {
        return 0.5;
    }
    // The top 53 bits: an integer every f64 represents exactly, scaled
    // into [0, 1).
    (u64::from_le_bytes(bytes) >> 11) as f64 / (1_u64 << 53) as f64
}

// ---------------------------------------------------------------------------
// The classifier
// ---------------------------------------------------------------------------

/// Why a pull attempt is worth retrying — the cause each retry logs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransientCause {
    /// HTTP 429 / `toomanyrequests` / "rate exceeded".
    RateLimited,
    /// The registry answered 500, 502, 503 or 504.
    RegistryUnavailable,
    /// The connection to the registry was reset or refused.
    ConnectionDropped,
    /// A TLS-handshake or request timeout talking to the registry.
    Timeout,
    /// The registry connection ended mid-download (unexpected EOF).
    TruncatedDownload,
}

impl fmt::Display for TransientCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::RateLimited => "registry rate limit",
            Self::RegistryUnavailable => "registry 5xx",
            Self::ConnectionDropped => "registry connection reset or refused",
            Self::Timeout => "registry timeout",
            Self::TruncatedDownload => "download cut short (unexpected EOF)",
        })
    }
}

/// What one failed attempt means for the next.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Wait and try again.
    Transient(TransientCause),
    /// Fail now, with the daemon's message.
    Permanent,
}

/// Markers of failures that are NEVER retried, matched case-insensitively
/// and checked FIRST: a message carrying one of these and a transient
/// marker (an auth error that also mentions a 503) is permanent.
const PERMANENT_MARKERS: &[&str] = &[
    // Authentication / authorization: a retry cannot fix credentials, and
    // hammering a registry with bad ones can lock the account.
    "unauthorized",
    "authentication required",
    "no basic auth credentials",
    "incorrect username or password",
    "denied",
    "forbidden",
    // The reference does not exist (or not for this platform).
    "manifest unknown",
    "name unknown",
    "not found",
    "does not exist",
    "no matching manifest",
    "invalid reference format",
    // Content verification: the digest pin doing its job.
    "verification failed",
    "digest mismatch",
    "unexpected commit digest",
];

/// Markers of transient registry failures, matched case-insensitively,
/// first match wins. Nothing outside this table (and the daemon's own 429)
/// is ever retried.
const TRANSIENT_MARKERS: &[(&str, TransientCause)] = &[
    ("toomanyrequests", TransientCause::RateLimited),
    ("too many requests", TransientCause::RateLimited),
    ("rate exceeded", TransientCause::RateLimited),
    // The 5xx reason phrases, as the daemon relays a registry's status
    // ("received unexpected HTTP status: 503 Service Unavailable").
    ("internal server error", TransientCause::RegistryUnavailable),
    ("bad gateway", TransientCause::RegistryUnavailable),
    ("service unavailable", TransientCause::RegistryUnavailable),
    ("gateway timeout", TransientCause::RegistryUnavailable),
    ("connection reset", TransientCause::ConnectionDropped),
    ("connection refused", TransientCause::ConnectionDropped),
    ("tls handshake timeout", TransientCause::Timeout),
    ("i/o timeout", TransientCause::Timeout),
    ("client.timeout exceeded", TransientCause::Timeout),
    ("timeout awaiting response headers", TransientCause::Timeout),
    ("context deadline exceeded", TransientCause::Timeout),
    ("unexpected eof", TransientCause::TruncatedDownload),
];

/// Classify a registry failure the daemon relayed: `status` is the daemon's
/// HTTP status when it answered with an error response (`None` for an error
/// inside the progress stream), `message` its text.
///
/// The daemon's own 401/403/404 are final whatever the text says; then a
/// permanent marker wins; then a 429 or a transient marker retries; anything
/// else — unrecognized text included — is permanent.
pub(crate) fn classify_message(status: Option<u16>, message: &str) -> Verdict {
    if matches!(status, Some(401 | 403 | 404)) {
        return Verdict::Permanent;
    }
    let message = message.to_ascii_lowercase();
    if PERMANENT_MARKERS
        .iter()
        .any(|marker| message.contains(marker))
    {
        return Verdict::Permanent;
    }
    if status == Some(429) {
        return Verdict::Transient(TransientCause::RateLimited);
    }
    TRANSIENT_MARKERS
        .iter()
        .find(|(marker, _)| message.contains(marker))
        .map_or(Verdict::Permanent, |&(_, cause)| Verdict::Transient(cause))
}

/// Classify a bollard error. Only the daemon's relayed registry answers are
/// candidates; every other variant is the conversation with the DAEMON
/// failing (I/O, a client timeout, decoding) — never a registry hiccup,
/// whatever its text says.
pub(crate) fn classify_bollard(error: &bollard::errors::Error) -> Verdict {
    use bollard::errors::Error;
    match error {
        Error::DockerResponseServerError {
            status_code,
            message,
        } => classify_message(Some(*status_code), message),
        Error::DockerStreamError { error } => classify_message(None, error),
        _ => Verdict::Permanent,
    }
}

/// Classify a failed testcontainers pull: its bollard cause when it is a
/// pull error, permanent for anything else (client setup, configuration).
pub(crate) fn classify(error: &TestcontainersError) -> Verdict {
    match error {
        TestcontainersError::Client(ClientError::PullImage { err, .. }) => classify_bollard(err),
        _ => Verdict::Permanent,
    }
}

// ---------------------------------------------------------------------------
// The seams: the daemon and the clock
// ---------------------------------------------------------------------------

/// One failed pull attempt: its verdict and the daemon's message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AttemptFailure {
    pub(crate) verdict: Verdict,
    pub(crate) message: String,
}

/// The daemon operations the pull path needs (unit tests script them).
pub(crate) trait ImageStore {
    /// Whether the daemon already holds `reference` (looked up by digest).
    async fn is_present(&self, reference: &str) -> Result<bool, String>;
    /// One pull attempt.
    async fn pull(&self, reference: &str) -> Result<(), AttemptFailure>;
}

/// The retry loop's time (unit tests advance it without sleeping).
pub(crate) trait Clock {
    /// Time since the pull started.
    fn elapsed(&self) -> Duration;
    /// Wait `wait`.
    async fn sleep(&self, wait: Duration);
}

/// The real daemon: the process's docker host, resolved exactly as
/// testcontainers resolves it ([`crate::docker`]).
struct Daemon;

impl ImageStore for Daemon {
    async fn is_present(&self, reference: &str) -> Result<bool, String> {
        let docker = crate::docker::try_connect()?;
        match docker.inspect_image(reference).await {
            Ok(_) => Ok(true),
            Err(bollard::errors::Error::DockerResponseServerError {
                status_code: 404, ..
            }) => Ok(false),
            Err(e) => Err(e.to_string()),
        }
    }

    async fn pull(&self, reference: &str) -> Result<(), AttemptFailure> {
        let (name, tag) = split_image(reference);
        GenericImage::new(name, tag)
            .pull_image()
            .await
            .map(drop)
            .map_err(|e| AttemptFailure {
                verdict: classify(&e),
                message: e.to_string(),
            })
    }
}

/// Wall-clock time on the tokio timer.
struct TokioClock(tokio::time::Instant);

impl Clock for TokioClock {
    fn elapsed(&self) -> Duration {
        self.0.elapsed()
    }

    async fn sleep(&self, wait: Duration) {
        tokio::time::sleep(wait).await;
    }
}

// ---------------------------------------------------------------------------
// Outcomes
// ---------------------------------------------------------------------------

/// How an image came to be present.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ensured {
    /// The daemon already held it: nothing was pulled.
    Present,
    /// Pulled, after `attempts` attempts (1 = no retry) over `elapsed`.
    Pulled {
        /// Attempts made, the successful one included.
        attempts: u32,
        /// Time from the first attempt to success.
        elapsed: Duration,
    },
}

/// Why an image could not be made present.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PullError {
    /// The reference is not a digest pin — refused before any daemon call.
    NotPinned {
        /// The refused reference.
        reference: String,
        /// What is wrong with it.
        problem: String,
    },
    /// The daemon could not say whether the image is present.
    Inspect {
        /// The image asked about.
        reference: String,
        /// The daemon (or connection) error.
        message: String,
    },
    /// A failure that is never retried (see the module docs).
    Permanent {
        /// The image being pulled.
        reference: String,
        /// Attempts made, the failing one included.
        attempts: u32,
        /// The daemon's message.
        message: String,
    },
    /// Transient failures outlasted [`PULL_RETRY_BUDGET`].
    BudgetSpent {
        /// The image being pulled.
        reference: String,
        /// Attempts made.
        attempts: u32,
        /// Time spent from the first attempt to giving up.
        elapsed: Duration,
        /// The last attempt's cause.
        cause: TransientCause,
        /// The last attempt's message.
        message: String,
    },
}

impl fmt::Display for PullError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotPinned { reference, problem } => write!(
                f,
                "refusing to pull {reference:?}: {problem} — every test image is a digest pin \
                 (name:tag@sha256:<64 hex>; a tag alone is mutable upstream)"
            ),
            Self::Inspect { reference, message } => write!(
                f,
                "could not ask the docker daemon whether {reference} is present: {message}"
            ),
            Self::Permanent {
                reference,
                attempts,
                message,
            } => write!(
                f,
                "pulling {reference} failed on attempt {attempts} with an error that is never \
                 retried (authentication, a missing manifest, a digest mismatch, or not a \
                 registry hiccup): {message}"
            ),
            Self::BudgetSpent {
                reference,
                attempts,
                elapsed,
                cause,
                message,
            } => write!(
                f,
                "pulling {reference} still failed after {attempts} attempts over {:.0}s \
                 ({cause}; the {}s retry budget is spent): {message} — the registry is \
                 throttling or down. A registry mirror or authenticated pulls raise the limit, \
                 and scripts/pull-test-images.sh warms the cache ahead of the suites (see the \
                 seaworthy-test-support crate docs, \"Image pulls\")",
                elapsed.as_secs_f64(),
                PULL_RETRY_BUDGET.as_secs()
            ),
        }
    }
}

impl std::error::Error for PullError {}

/// One retry about to happen — the facts its log line carries.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Retry<'a> {
    pub(crate) reference: &'a str,
    /// The attempt that just failed, 1-based.
    pub(crate) attempt: u32,
    pub(crate) cause: TransientCause,
    pub(crate) message: &'a str,
    pub(crate) wait: Duration,
    pub(crate) elapsed: Duration,
}

impl fmt::Display for Retry<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "seaworthy-test-support: pulling {}: attempt {} hit a transient {}: {} — retrying in \
             {:.1}s ({:.0}s of the {}s pull budget spent)",
            self.reference,
            self.attempt,
            self.cause,
            self.message,
            self.wait.as_secs_f64(),
            self.elapsed.as_secs_f64(),
            PULL_RETRY_BUDGET.as_secs()
        )
    }
}

// ---------------------------------------------------------------------------
// The pull path
// ---------------------------------------------------------------------------

/// Make sure the daemon holds the digest-pinned `reference`, pulling it —
/// with transient registry failures retried — only when it is absent. See
/// the module docs for what is and is never retried.
///
/// # Errors
/// [`PullError`]: an unpinned reference, an unanswerable presence check, a
/// permanent pull failure, or a spent retry budget.
pub async fn ensure_image(reference: &str) -> Result<Ensured, PullError> {
    let clock = TokioClock(tokio::time::Instant::now());
    ensure_with(
        &Daemon,
        &clock,
        rand01,
        |retry| eprintln!("{retry}"),
        reference,
    )
    .await
}

/// [`ensure_image`] over injected seams.
pub(crate) async fn ensure_with(
    store: &impl ImageStore,
    clock: &impl Clock,
    rand01: impl FnMut() -> f64,
    on_retry: impl FnMut(&Retry<'_>),
    reference: &str,
) -> Result<Ensured, PullError> {
    images::validate_pin(reference).map_err(|problem| PullError::NotPinned {
        reference: reference.to_string(),
        problem,
    })?;
    match store.is_present(reference).await {
        Ok(true) => Ok(Ensured::Present),
        Ok(false) => pull_with_retries(store, clock, rand01, on_retry, reference).await,
        Err(message) => Err(PullError::Inspect {
            reference: reference.to_string(),
            message,
        }),
    }
}

/// The retry loop: attempt, classify, and — for a transient failure whose
/// jittered wait still fits the budget — log, wait, and try again.
async fn pull_with_retries(
    store: &impl ImageStore,
    clock: &impl Clock,
    mut rand01: impl FnMut() -> f64,
    mut on_retry: impl FnMut(&Retry<'_>),
    reference: &str,
) -> Result<Ensured, PullError> {
    let mut attempt = 0_u32;
    loop {
        attempt += 1;
        let failure = match store.pull(reference).await {
            Ok(()) => {
                return Ok(Ensured::Pulled {
                    attempts: attempt,
                    elapsed: clock.elapsed(),
                });
            }
            Err(failure) => failure,
        };
        let Verdict::Transient(cause) = failure.verdict else {
            return Err(PullError::Permanent {
                reference: reference.to_string(),
                attempts: attempt,
                message: failure.message,
            });
        };
        let wait = jittered(nominal_wait(attempt), rand01());
        let elapsed = clock.elapsed();
        if elapsed.saturating_add(wait) > PULL_RETRY_BUDGET {
            return Err(PullError::BudgetSpent {
                reference: reference.to_string(),
                attempts: attempt,
                elapsed,
                cause,
                message: failure.message,
            });
        }
        on_retry(&Retry {
            reference,
            attempt,
            cause,
            message: &failure.message,
            wait,
            elapsed,
        });
        clock.sleep(wait).await;
    }
}

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        collections::VecDeque,
        time::Duration,
    };

    use bollard::errors::Error as BollardError;
    use testcontainers::{TestcontainersError, core::error::ClientError};

    use super::{
        AttemptFailure, Clock, Ensured, ImageStore, PULL_RETRY_BUDGET, PullError, Retry,
        TransientCause::{self, *},
        Verdict::{self, Permanent, Transient},
        classify, classify_bollard, classify_message, ensure_with, jittered, nominal_wait,
    };
    use crate::images;

    const PIN: &str = images::DEBIAN_13;

    fn secs(s: u64) -> Duration {
        Duration::from_secs(s)
    }

    fn stream(message: &str) -> BollardError {
        BollardError::DockerStreamError {
            error: message.to_string(),
        }
    }

    fn server(status_code: u16, message: &str) -> BollardError {
        BollardError::DockerResponseServerError {
            status_code,
            message: message.to_string(),
        }
    }

    // ---- the classifier ----------------------------------------------------

    /// Each registry's rate-limit answer retries: every marker carried
    /// alone by at least one row.
    #[test]
    fn rate_limits_are_transient() {
        for message in [
            // public.ecr.aws.
            "toomanyrequests: Rate exceeded",
            // ghcr.io: the error code alone.
            "toomanyrequests: retry-after: 785.938µs, allowed: 44000/minute",
            // Docker Hub: "authenticating" is advice, not an auth failure.
            "toomanyrequests: You have reached your pull rate limit. You may increase the limit \
             by authenticating and upgrading: https://www.docker.com/increase-rate-limit",
            // The reason phrase alone, and the ECR wording alone.
            "received unexpected HTTP status: 429 Too Many Requests",
            "Rate exceeded",
            "TOOMANYREQUESTS: RATE EXCEEDED",
        ] {
            assert_eq!(
                classify_message(None, message),
                Transient(RateLimited),
                "{message}"
            );
        }
        assert_eq!(classify_message(Some(429), ""), Transient(RateLimited));
        assert_eq!(
            classify_message(Some(500), "toomanyrequests: Rate exceeded"),
            Transient(RateLimited)
        );
    }

    #[test]
    fn registry_5xx_resets_timeouts_and_truncated_downloads_are_transient() {
        for (message, cause) in [
            (
                "received unexpected HTTP status: 500 Internal Server Error",
                RegistryUnavailable,
            ),
            (
                "received unexpected HTTP status: 502 Bad Gateway",
                RegistryUnavailable,
            ),
            (
                "received unexpected HTTP status: 503 Service Unavailable",
                RegistryUnavailable,
            ),
            (
                "received unexpected HTTP status: 504 Gateway Timeout",
                RegistryUnavailable,
            ),
            (
                "read tcp 172.17.0.2:45678->3.216.34.172:443: read: connection reset by peer",
                ConnectionDropped,
            ),
            (
                "dial tcp 3.216.34.172:443: connect: connection refused",
                ConnectionDropped,
            ),
            (
                "Get \"https://public.ecr.aws/v2/\": net/http: TLS handshake timeout",
                Timeout,
            ),
            ("dial tcp 104.16.99.52:443: i/o timeout", Timeout),
            (
                "Get \"https://ghcr.io/v2/\": net/http: request canceled (Client.Timeout \
                 exceeded while awaiting headers)",
                Timeout,
            ),
            ("net/http: timeout awaiting response headers", Timeout),
            (
                "failed to copy: httpReadSeeker: failed open: context deadline exceeded",
                Timeout,
            ),
            (
                "error pulling image configuration: download failed after attempts=6: \
                 unexpected EOF",
                TruncatedDownload,
            ),
        ] {
            assert_eq!(
                classify_message(None, message),
                Transient(cause),
                "{message}"
            );
        }
    }

    /// Auth, missing manifests, digest failures, offline machines, and
    /// anything unrecognized fail at once.
    #[test]
    fn auth_missing_manifests_and_digest_failures_are_never_retried() {
        for message in [
            "pull access denied for acme/nope, repository does not exist or may require \
             'docker login': denied: requested access to the resource is denied",
            "unauthorized: authentication required",
            "Head \"https://ghcr.io/v2/acme/x/manifests/1\": unauthorized",
            "no basic auth credentials",
            "unauthorized: incorrect username or password",
            "received unexpected HTTP status: 403 Forbidden",
            "manifest for acme/tool:1.8 not found: manifest unknown: manifest unknown",
            "name unknown: repository name not known to registry",
            "no matching manifest for linux/arm64/v8 in the manifest list entries",
            "invalid reference format",
            "filesystem layer verification failed for digest sha256:24220ef2",
            "manifest verification failed for digest sha256:24220ef2",
            "unexpected commit digest sha256:aaaa, expected sha256:bbbb: failed precondition",
            "digest mismatch",
            // Not on the transient list: an offline machine fails now.
            "dial tcp: lookup registry-1.docker.io on 127.0.0.11:53: no such host",
            "dial tcp 3.216.34.172:443: connect: network is unreachable",
            // Unrecognized text is never guessed transient.
            "something nobody has seen before",
            "",
        ] {
            assert_eq!(classify_message(None, message), Permanent, "{message:?}");
        }
        // Docker 29 (containerd image store) on an unknown digest, as
        // recorded live.
        let unknown_digest = "failed to resolve reference \
             \"docker.io/library/busybox:1.37.0@sha256:ffff\": \
             docker.io/library/busybox:1.37.0@sha256:ffff: not found";
        assert_eq!(classify_message(Some(404), unknown_digest), Permanent);
        assert_eq!(classify_message(None, unknown_digest), Permanent);
        // A permanent marker wins over a transient one in the same text —
        // one row per marker, each carrying that marker ALONE next to
        // transient noise (a removed marker turns its row red).
        for message in [
            "Head \"https://ghcr.io/v2/x/manifests/1\": unauthorized (after a 503 Service \
             Unavailable)",
            "authentication required — retry after connection reset",
            "no basic auth credentials (i/o timeout)",
            "incorrect username or password (TLS handshake timeout)",
            "denied: requested access to the resource (toomanyrequests)",
            "403 Forbidden (unexpected EOF)",
            "toomanyrequests: manifest unknown",
            "name unknown (connection refused)",
            "manifest for x:1 not found (Bad Gateway)",
            "repository does not exist (Gateway Timeout)",
            "no matching manifest for linux/arm64 (rate exceeded)",
            "invalid reference format (too many requests)",
            "filesystem layer verification failed (unexpected EOF)",
            "digest mismatch (connection reset by peer)",
            "unexpected commit digest sha256:aa (context deadline exceeded)",
        ] {
            assert_eq!(classify_message(None, message), Permanent, "{message:?}");
        }
        // The daemon's own auth / missing statuses are final, whatever the text.
        for status in [401, 403, 404] {
            assert_eq!(
                classify_message(Some(status), "toomanyrequests: Rate exceeded"),
                Permanent,
                "{status}"
            );
        }
    }

    /// Only the daemon's relayed registry answers are candidates: a failure
    /// talking to the daemon itself is never retried, whatever its text.
    #[test]
    fn only_registry_answers_relayed_by_the_daemon_are_classified() {
        assert_eq!(
            classify_bollard(&stream("toomanyrequests: Rate exceeded")),
            Transient(RateLimited)
        );
        assert_eq!(
            classify_bollard(&server(500, "toomanyrequests: Rate exceeded")),
            Transient(RateLimited)
        );
        assert_eq!(classify_bollard(&server(429, "")), Transient(RateLimited));
        assert_eq!(
            classify_bollard(&server(404, "manifest unknown")),
            Permanent
        );
        let daemon_refused = BollardError::IOError {
            err: std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "connection refused"),
        };
        assert_eq!(classify_bollard(&daemon_refused), Permanent);
        assert_eq!(
            classify_bollard(&BollardError::RequestTimeoutError),
            Permanent
        );
    }

    /// testcontainers' pull error is unwrapped to its bollard cause; nothing
    /// that is not a pull (client setup, start, readiness, a port
    /// collision) is ever classified transient.
    #[test]
    fn testcontainers_pull_errors_are_unwrapped_and_nothing_else_is_retried() {
        let pull = |err| {
            TestcontainersError::Client(ClientError::PullImage {
                descriptor: PIN.to_string(),
                err,
            })
        };
        let incident = pull(stream("toomanyrequests: Rate exceeded"));
        // A rate-limited pull, as testcontainers renders it.
        assert!(
            incident
                .to_string()
                .contains("failed to pull the image 'debian:13@sha256:"),
            "{incident}"
        );
        assert_eq!(classify(&incident), Transient(RateLimited));
        assert_eq!(classify(&pull(server(404, "manifest unknown"))), Permanent);
        assert_eq!(
            classify(&TestcontainersError::Client(ClientError::Init(stream(
                "toomanyrequests"
            )))),
            Permanent
        );
        assert_eq!(
            classify(&TestcontainersError::other(
                "port is already allocated (toomanyrequests)"
            )),
            Permanent
        );
        assert_eq!(
            classify(&TestcontainersError::Io(std::io::Error::other(
                "unexpected EOF"
            ))),
            Permanent
        );
    }

    // ---- the schedule ------------------------------------------------------

    #[test]
    fn waits_double_from_two_seconds_and_cap_at_thirty() {
        let schedule: Vec<_> = (1..=7).map(nominal_wait).collect();
        assert_eq!(
            schedule,
            [
                secs(2),
                secs(4),
                secs(8),
                secs(16),
                secs(30),
                secs(30),
                secs(30)
            ]
        );
        assert_eq!(nominal_wait(0), secs(2), "defensive: attempt 0 reads as 1");
        assert_eq!(nominal_wait(u32::MAX), secs(30), "no overflow");
        let nine: Duration = (1..=9).map(nominal_wait).sum();
        assert_eq!(
            nine, PULL_RETRY_BUDGET,
            "the nominal schedule is nine waits"
        );
    }

    #[test]
    fn jitter_stays_between_half_and_all_of_the_schedule() {
        assert_eq!(jittered(secs(30), 0.0), secs(15));
        assert_eq!(jittered(secs(30), 1.0), secs(30));
        assert_eq!(jittered(secs(30), 0.5), Duration::from_millis(22_500));
        assert_eq!(jittered(secs(30), -3.0), secs(15), "clamped");
        assert_eq!(jittered(secs(30), 7.0), secs(30), "clamped");
        assert_eq!(
            jittered(secs(30), f64::NAN),
            Duration::from_millis(22_500),
            "NaN reads as the midpoint"
        );
        for _ in 0..1_000 {
            let draw = super::rand01();
            assert!((0.0..=1.0).contains(&draw), "{draw}");
        }
    }

    // ---- the retry loop, over scripted seams -------------------------------

    /// A scripted daemon: a presence answer, then pull results in order,
    /// then (optionally) one failure forever. Every scripted failure goes
    /// through the REAL classifier.
    struct FakeStore {
        present: Result<bool, String>,
        script: RefCell<VecDeque<Result<(), BollardError>>>,
        forever: Option<fn() -> BollardError>,
        inspects: Cell<u32>,
        pulls: Cell<u32>,
    }

    impl FakeStore {
        fn absent(script: impl IntoIterator<Item = Result<(), BollardError>>) -> Self {
            Self {
                present: Ok(false),
                script: RefCell::new(script.into_iter().collect()),
                forever: None,
                inspects: Cell::new(0),
                pulls: Cell::new(0),
            }
        }

        fn failing_forever(error: fn() -> BollardError) -> Self {
            Self {
                forever: Some(error),
                ..Self::absent([])
            }
        }

        fn present(answer: Result<bool, String>) -> Self {
            Self {
                present: answer,
                ..Self::absent([])
            }
        }
    }

    impl ImageStore for FakeStore {
        async fn is_present(&self, _: &str) -> Result<bool, String> {
            self.inspects.set(self.inspects.get() + 1);
            self.present.clone()
        }

        async fn pull(&self, _: &str) -> Result<(), AttemptFailure> {
            self.pulls.set(self.pulls.get() + 1);
            // A loop without a working budget fails here, fast, instead of
            // spinning on the fake clock until the runner's kill timeout.
            assert!(self.pulls.get() <= 1_000, "the retries are unbounded");
            let next = self.script.borrow_mut().pop_front();
            let result = match (next, self.forever) {
                (Some(result), _) => result,
                (None, Some(error)) => Err(error()),
                (None, None) => panic!("pulled more often than scripted"),
            };
            result.map_err(|e| AttemptFailure {
                verdict: classify_bollard(&e),
                message: e.to_string(),
            })
        }
    }

    /// Time that only moves when the loop sleeps; records every wait.
    #[derive(Default)]
    struct FakeClock {
        now: Cell<Duration>,
        waits: RefCell<Vec<Duration>>,
    }

    impl Clock for FakeClock {
        fn elapsed(&self) -> Duration {
            self.now.get()
        }

        async fn sleep(&self, wait: Duration) {
            self.now.set(self.now.get() + wait);
            self.waits.borrow_mut().push(wait);
        }
    }

    async fn ensure(
        store: &FakeStore,
        clock: &FakeClock,
        draw: f64,
        reference: &str,
    ) -> (Result<Ensured, PullError>, Vec<String>) {
        let mut log = Vec::new();
        let outcome = ensure_with(
            store,
            clock,
            || draw,
            |retry: &Retry<'_>| log.push(retry.to_string()),
            reference,
        )
        .await;
        (outcome, log)
    }

    /// Transient failures are retried inside the launcher's pull until it
    /// succeeds (the test body never sees them), and every retry is logged
    /// with its cause and the daemon's message.
    #[tokio::test]
    async fn transient_failures_are_retried_until_the_pull_succeeds() {
        let store = FakeStore::absent([
            Err(stream(
                "toomanyrequests: retry-after: 785.938µs, allowed: 44000/minute",
            )),
            Err(stream(
                "received unexpected HTTP status: 503 Service Unavailable",
            )),
            Ok(()),
        ]);
        let clock = FakeClock::default();
        let (outcome, log) = ensure(&store, &clock, 1.0, PIN).await;
        assert_eq!(
            outcome,
            Ok(Ensured::Pulled {
                attempts: 3,
                elapsed: secs(6)
            })
        );
        assert_eq!(store.pulls.get(), 3);
        assert_eq!(*clock.waits.borrow(), [secs(2), secs(4)]);
        assert_eq!(log.len(), 2, "{log:?}");
        assert!(
            log[0].contains(PIN)
                && log[0].contains("attempt 1")
                && log[0].contains("registry rate limit")
                && log[0].contains("toomanyrequests")
                && log[0].contains("retrying in 2.0s"),
            "{}",
            log[0]
        );
        assert!(
            log[1].contains("attempt 2")
                && log[1].contains("registry 5xx")
                && log[1].contains("503 Service Unavailable"),
            "{}",
            log[1]
        );
    }

    /// Jitter shortens the waits, never lengthens them.
    #[tokio::test]
    async fn the_jittered_waits_never_exceed_the_schedule() {
        let store = FakeStore::absent([
            Err(stream("toomanyrequests: Rate exceeded")),
            Err(stream("toomanyrequests: Rate exceeded")),
            Ok(()),
        ]);
        let clock = FakeClock::default();
        let (outcome, _) = ensure(&store, &clock, 0.0, PIN).await;
        assert!(matches!(outcome, Ok(Ensured::Pulled { attempts: 3, .. })));
        assert_eq!(*clock.waits.borrow(), [secs(1), secs(2)]);
    }

    /// Auth, a missing manifest, and a digest-verification failure stop at
    /// the first attempt: no wait, no second pull.
    #[tokio::test]
    async fn a_permanent_failure_is_never_retried() {
        for error in [
            server(404, "manifest unknown"),
            stream("unauthorized: authentication required"),
            stream("filesystem layer verification failed for digest sha256:24220ef2"),
            BollardError::RequestTimeoutError,
        ] {
            let text = error.to_string();
            let store = FakeStore::absent([Err(error), Ok(())]);
            let clock = FakeClock::default();
            let (outcome, log) = ensure(&store, &clock, 1.0, PIN).await;
            assert_eq!(
                outcome,
                Err(PullError::Permanent {
                    reference: PIN.to_string(),
                    attempts: 1,
                    message: text.clone(),
                }),
                "{text}"
            );
            assert_eq!(store.pulls.get(), 1, "{text}: pulled again");
            assert!(clock.waits.borrow().is_empty() && log.is_empty(), "{text}");
        }
    }

    /// A permanent failure after transient ones ends the retries there.
    #[tokio::test]
    async fn a_permanent_failure_after_transient_ones_ends_the_retries() {
        let store = FakeStore::absent([
            Err(stream("toomanyrequests: Rate exceeded")),
            Err(stream("unexpected EOF")),
            Err(stream("unauthorized: authentication required")),
            Ok(()),
        ]);
        let clock = FakeClock::default();
        let (outcome, log) = ensure(&store, &clock, 1.0, PIN).await;
        assert!(
            matches!(outcome, Err(PullError::Permanent { attempts: 3, .. })),
            "{outcome:?}"
        );
        assert_eq!(store.pulls.get(), 3);
        assert_eq!(log.len(), 2);
    }

    /// A registry that never recovers is bounded by the budget: at the full
    /// schedule, nine waits (2+4+8+16+30·5 = 180 s) and ten attempts; with
    /// jitter at its shortest, more attempts but never past the budget.
    #[tokio::test]
    async fn the_budget_bounds_a_registry_that_never_recovers() {
        let store = FakeStore::failing_forever(|| stream("toomanyrequests: Rate exceeded"));
        let clock = FakeClock::default();
        let (outcome, log) = ensure(&store, &clock, 1.0, PIN).await;
        assert_eq!(
            outcome,
            Err(PullError::BudgetSpent {
                reference: PIN.to_string(),
                attempts: 10,
                elapsed: PULL_RETRY_BUDGET,
                cause: RateLimited,
                message: "Docker stream error: toomanyrequests: Rate exceeded".to_string(),
            })
        );
        assert_eq!(
            *clock.waits.borrow(),
            [
                secs(2),
                secs(4),
                secs(8),
                secs(16),
                secs(30),
                secs(30),
                secs(30),
                secs(30),
                secs(30)
            ]
        );
        assert_eq!(log.len(), 9);

        let store = FakeStore::failing_forever(|| stream("connection reset by peer"));
        let clock = FakeClock::default();
        let (outcome, _) = ensure(&store, &clock, 0.0, PIN).await;
        let Err(PullError::BudgetSpent {
            attempts, cause, ..
        }) = outcome
        else {
            panic!("expected the budget to run out: {outcome:?}");
        };
        assert_eq!(cause, ConnectionDropped);
        let waited: Duration = clock.waits.borrow().iter().sum();
        assert!(waited <= PULL_RETRY_BUDGET, "{waited:?}");
        assert!(
            waited + secs(15) > PULL_RETRY_BUDGET,
            "gave up early: {waited:?}"
        );
        assert_eq!(attempts, store.pulls.get());
        assert!(attempts > 10, "shorter waits fit more attempts: {attempts}");
    }

    /// A present image costs one presence check and no registry traffic.
    #[tokio::test]
    async fn present_images_are_never_pulled() {
        let store = FakeStore::present(Ok(true));
        let (outcome, _) = ensure(&store, &FakeClock::default(), 1.0, PIN).await;
        assert_eq!(outcome, Ok(Ensured::Present));
        assert_eq!((store.inspects.get(), store.pulls.get()), (1, 0));
    }

    /// A reference that is not a digest pin never reaches the daemon:
    /// neither the presence check nor a pull.
    #[tokio::test]
    async fn unpinned_references_are_refused_before_the_daemon_is_asked() {
        for reference in [
            "acme/tool:1.8.1.3",
            "acme/tool:latest",
            "acme/tool",
            "acme/tool@sha256:24220ef2c80a2a421ea08e4624488e985330c421b6aa3329bae14b0933a1d403",
        ] {
            let store = FakeStore::absent([Ok(())]);
            let (outcome, _) = ensure(&store, &FakeClock::default(), 1.0, reference).await;
            assert!(
                matches!(&outcome, Err(PullError::NotPinned { reference: r, .. }) if r == reference),
                "{reference}: {outcome:?}"
            );
            assert_eq!((store.inspects.get(), store.pulls.get()), (0, 0));
        }
    }

    /// A presence check the daemon cannot answer fails without a pull.
    #[tokio::test]
    async fn an_unanswerable_presence_check_fails_without_pulling() {
        let store = FakeStore::present(Err("daemon went away".into()));
        let (outcome, _) = ensure(&store, &FakeClock::default(), 1.0, PIN).await;
        assert_eq!(
            outcome,
            Err(PullError::Inspect {
                reference: PIN.to_string(),
                message: "daemon went away".into()
            })
        );
        assert_eq!(store.pulls.get(), 0);
    }

    #[test]
    fn pull_errors_name_the_image_and_the_way_out() {
        let spent = PullError::BudgetSpent {
            reference: PIN.to_string(),
            attempts: 10,
            elapsed: PULL_RETRY_BUDGET,
            cause: RateLimited,
            message: "toomanyrequests: Rate exceeded".into(),
        }
        .to_string();
        for needle in [
            PIN,
            "10 attempts",
            "registry rate limit",
            "180s retry budget",
            "registry mirror or authenticated pulls",
            "scripts/pull-test-images.sh",
        ] {
            assert!(spent.contains(needle), "{needle:?} missing from: {spent}");
        }
        let unpinned = PullError::NotPinned {
            reference: "acme/tool:1.8.1.3".into(),
            problem: "not digest-pinned".into(),
        }
        .to_string();
        assert!(unpinned.contains("digest pin"), "{unpinned}");
        let cause: &dyn std::fmt::Display = &TransientCause::TruncatedDownload;
        assert_eq!(cause.to_string(), "download cut short (unexpected EOF)");
        let _: Verdict = Permanent;
    }

    // ---- live (skips without a daemon) -------------------------------------

    /// The real daemon seam: a pin is made present (pulling it, with the
    /// retry policy, on a cold daemon), after which it is never pulled
    /// again; an unknown digest reads as absent without a pull.
    #[tokio::test]
    async fn live_a_present_pin_is_not_pulled_again() {
        if !crate::docker_or_skip().await {
            return;
        }
        let first = super::ensure_image(PIN).await;
        assert!(first.is_ok(), "{first:?}");
        assert_eq!(super::ensure_image(PIN).await, Ok(Ensured::Present));
        let unknown = format!("debian:13@sha256:{}", "0".repeat(64));
        assert_eq!(super::Daemon.is_present(&unknown).await, Ok(false));
    }
}
