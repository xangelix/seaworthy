//! The TLS policy: ONE process-wide, boot-time description of what every
//! seaworthy TLS client offers (key-exchange groups, the minimum protocol
//! version, "hybrid required", and the cipher-suite profile) and the
//! provider built from it ([`crate::tls_provider`]). Only the client side is
//! here: [`client_config_builder`] is what the update helper's HTTPS client
//! builds on.
//!
//! # Why a policy and not rustls's defaults
//!
//! - **An explicit group order.** `rustls::crypto::aws_lc_rs::default_provider()`
//!   orders its groups by rustls's `prefer-post-quantum` cargo feature,
//!   which another crate in the graph may or may not turn on through feature
//!   unification. A graph without it would lead every client with a
//!   classical group, silently. The policy lists the groups explicitly, in
//!   order, so the order is a value this crate owns (and
//!   `prefer-post-quantum` is also enabled here, for the third-party code
//!   that still builds rustls's own default).
//! - **The P-256 hybrid.** The policy offers `SECP256R1MLKEM768` right after
//!   `X25519MLKEM768`: a FIPS-mode peer whose provider cannot do X25519 (as
//!   on RHEL in FIPS mode) can still negotiate a hybrid instead of falling
//!   back to classical P-256/P-384. `SecP384r1MLKEM1024` is not offered:
//!   rustls 0.23 does not implement it (it arrives with rustls 0.24,
//!   codepoint `0x11ed`), and this crate does not hand-roll TLS key-exchange
//!   constructions.
//! - **A boot-time setting.** The policy has published keys
//!   ([`BOOTSTRAP_KEYS`]: `SEAWORTHY_TLS_GROUPS`, `SEAWORTHY_TLS_MIN_VERSION`,
//!   `SEAWORTHY_TLS_REQUIRE_HYBRID`, `SEAWORTHY_TLS_SUITES`, read through
//!   [`TlsPolicy::from_config`], typically from the process environment),
//!   installed once ([`install_policy`]) before the first provider read. A
//!   deployment can require hybrid, drop TLS 1.2 or narrow the suites
//!   without a rebuild.
//!
//! # Defaults
//!
//! | build | groups (in preference order) |
//! |---|---|
//! | default | `X25519MLKEM768`, `SECP256R1MLKEM768`, `X25519`, `SECP256R1`, `SECP384R1` |
//! | `fips` | `X25519MLKEM768`, `SECP256R1MLKEM768`, `SECP256R1`, `SECP384R1` (X25519 is not approved) |
//!
//! TLS 1.2 + 1.3 (as far as the rustls build supports them), hybrid not
//! required, the full suite list (AES-256-GCM first).
//!
//! # How each knob is enforced
//!
//! Every knob lives IN the provider, so it reaches every consumer of
//! [`crate::tls_provider`], and of the process default
//! ([`crate::install_default_tls_provider`]), whatever protocol-version
//! list a builder passes:
//!
//! - groups / hybrid-required: the provider's `kx_groups`;
//! - minimum TLS 1.3: the provider carries no TLS 1.2 cipher suite (rustls
//!   only offers or accepts a version the provider has a suite for), and
//!   [`protocol_versions`] answers `[TLS13]`;
//! - the `aes256` suite profile: the provider carries only AES-256-GCM
//!   suites.
//!
//! # FIPS
//!
//! Under the `fips` feature [`TlsPolicy::validate`] refuses a group the
//! module does not approve (X25519) and the default list omits it. The
//! hybrid groups are admitted on rustls's SP 800-56Cr2 reading, where the
//! approved component's position decides (ML-KEM-768 leads
//! `X25519MLKEM768`; P-256 leads `SECP256R1MLKEM768`, whose two halves are
//! both approved). That reading is for your assessor to confirm; see
//! `docs/fips.md`.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use rustls::crypto::aws_lc_rs::{self, kx_group};
use rustls::crypto::{CryptoProvider, SupportedKxGroup};
use rustls::{CipherSuite, NamedGroup, SupportedCipherSuite, SupportedProtocolVersion};

// ---------------------------------------------------------------------------
// Config keys
// ---------------------------------------------------------------------------

/// Comma-separated key-exchange groups, in preference order (names as
/// [`KxGroup::name`], case-insensitive), e.g.
/// `X25519MLKEM768,SECP256R1MLKEM768,SECP256R1`. Absent = the default list.
pub const GROUPS_KEY: &str = "SEAWORTHY_TLS_GROUPS";
/// The minimum protocol version: `1.2` (default) or `1.3`.
pub const MIN_VERSION_KEY: &str = "SEAWORTHY_TLS_MIN_VERSION";
/// `true` keeps only post-quantum groups (hybrid, or pure ML-KEM when
/// configured): every client built on the policy then refuses a
/// classical-only peer at the handshake. Default `false`.
pub const REQUIRE_HYBRID_KEY: &str = "SEAWORTHY_TLS_REQUIRE_HYBRID";
/// The cipher-suite profile: `default`, or `aes256` (AES-256-GCM only: no
/// AES-128, no ChaCha20).
pub const SUITES_KEY: &str = "SEAWORTHY_TLS_SUITES";

/// Every key [`TlsPolicy::from_config`] reads. They are SOURCE BOOTSTRAP,
/// not store-held configuration: the policy governs every TLS connection
/// the process makes, a remote configuration store's fetch included, so such
/// a store cannot carry the policy needed to reach it. Read them from the
/// process environment and declare them beside the application's other
/// bootstrap keys.
pub const BOOTSTRAP_KEYS: &[&str] = &[GROUPS_KEY, MIN_VERSION_KEY, REQUIRE_HYBRID_KEY, SUITES_KEY];

/// The most groups a policy may list (every group this crate knows, once).
pub const MAX_GROUPS: usize = KxGroup::ALL.len();

// ---------------------------------------------------------------------------
// Vocabulary
// ---------------------------------------------------------------------------

/// A key-exchange group the canonical provider can offer: exactly the
/// groups rustls 0.23's AWS-LC provider implements.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KxGroup {
    /// X25519 + ML-KEM-768 (draft-ietf-tls-ecdhe-mlkem, `0x11ec`).
    X25519Mlkem768,
    /// NIST P-256 + ML-KEM-768 (`0x11eb`): both halves FIPS-approved.
    Secp256r1Mlkem768,
    /// Pure ML-KEM-768 (`0x0201`): post-quantum without a classical hedge.
    Mlkem768,
    /// Pure ML-KEM-1024 (`0x0202`).
    Mlkem1024,
    /// Classical X25519 (`0x001d`): not FIPS-approved.
    X25519,
    /// Classical NIST P-256 (`0x0017`).
    Secp256r1,
    /// Classical NIST P-384 (`0x0018`).
    Secp384r1,
}

impl KxGroup {
    /// Every group, in the default preference order of the non-FIPS list
    /// followed by the opt-in pure ML-KEM groups.
    pub const ALL: [Self; 7] = [
        Self::X25519Mlkem768,
        Self::Secp256r1Mlkem768,
        Self::X25519,
        Self::Secp256r1,
        Self::Secp384r1,
        Self::Mlkem768,
        Self::Mlkem1024,
    ];

    /// The config / log name (`X25519MLKEM768`, `SECP256R1MLKEM768`, …).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::X25519Mlkem768 => "X25519MLKEM768",
            Self::Secp256r1Mlkem768 => "SECP256R1MLKEM768",
            Self::Mlkem768 => "MLKEM768",
            Self::Mlkem1024 => "MLKEM1024",
            Self::X25519 => "X25519",
            Self::Secp256r1 => "SECP256R1",
            Self::Secp384r1 => "SECP384R1",
        }
    }

    /// Parse a config name, case-insensitively (also the IANA / OpenSSL
    /// spellings `SecP256r1MLKEM768`, `secp256r1`, `prime256v1`, `P-256`,
    /// `P-384`).
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        let lower = name.trim().to_ascii_lowercase();
        Some(match lower.as_str() {
            "x25519mlkem768" => Self::X25519Mlkem768,
            "secp256r1mlkem768" => Self::Secp256r1Mlkem768,
            "mlkem768" => Self::Mlkem768,
            "mlkem1024" => Self::Mlkem1024,
            "x25519" => Self::X25519,
            "secp256r1" | "prime256v1" | "p-256" => Self::Secp256r1,
            "secp384r1" | "p-384" => Self::Secp384r1,
            _ => return None,
        })
    }

    /// The group for a rustls [`NamedGroup`], if this crate knows it.
    #[must_use]
    pub fn from_named_group(group: NamedGroup) -> Option<Self> {
        Self::ALL.into_iter().find(|g| g.named_group() == group)
    }

    /// The rustls wire identifier.
    #[must_use]
    pub const fn named_group(self) -> NamedGroup {
        match self {
            Self::X25519Mlkem768 => NamedGroup::X25519MLKEM768,
            Self::Secp256r1Mlkem768 => NamedGroup::secp256r1MLKEM768,
            Self::Mlkem768 => NamedGroup::MLKEM768,
            Self::Mlkem1024 => NamedGroup::MLKEM1024,
            Self::X25519 => NamedGroup::X25519,
            Self::Secp256r1 => NamedGroup::secp256r1,
            Self::Secp384r1 => NamedGroup::secp384r1,
        }
    }

    /// A classical ECDHE share combined with ML-KEM.
    #[must_use]
    pub const fn is_hybrid(self) -> bool {
        matches!(self, Self::X25519Mlkem768 | Self::Secp256r1Mlkem768)
    }

    /// Carries an ML-KEM component (hybrid or pure): what "hybrid
    /// required" admits.
    #[must_use]
    pub const fn is_post_quantum(self) -> bool {
        matches!(
            self,
            Self::X25519Mlkem768 | Self::Secp256r1Mlkem768 | Self::Mlkem768 | Self::Mlkem1024
        )
    }

    /// Whether the AWS-LC-FIPS module approves the group (everything but
    /// X25519; see the module docs for the hybrid reading).
    #[must_use]
    pub const fn approved_under_fips(self) -> bool {
        !matches!(self, Self::X25519)
    }

    /// rustls's implementation of the group (AWS-LC).
    fn rustls(self) -> &'static dyn SupportedKxGroup {
        match self {
            Self::X25519Mlkem768 => kx_group::X25519MLKEM768,
            Self::Secp256r1Mlkem768 => kx_group::SECP256R1MLKEM768,
            Self::Mlkem768 => kx_group::MLKEM768,
            Self::Mlkem1024 => kx_group::MLKEM1024,
            Self::X25519 => kx_group::X25519,
            Self::Secp256r1 => kx_group::SECP256R1,
            Self::Secp384r1 => kx_group::SECP384R1,
        }
    }
}

impl fmt::Display for KxGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Whether a negotiated group carries an ML-KEM component. Groups this
/// crate does not know (including `SecP384r1MLKEM1024`, codepoint `0x11ed`,
/// and pure `MLKEM512`) are judged by codepoint, so a newer peer is
/// classified correctly.
#[must_use]
pub fn is_post_quantum_group(group: NamedGroup) -> bool {
    matches!(u16::from(group), 0x0200..=0x0202 | 0x11eb..=0x11ed)
}

/// The minimum protocol version.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum MinTlsVersion {
    /// TLS 1.2 and 1.3 (the default).
    #[default]
    Tls12,
    /// TLS 1.3 only: the hybrid groups are TLS 1.3-only, and the record
    /// layer then always uses the module's TLS 1.3 IV construction.
    Tls13,
}

impl MinTlsVersion {
    /// Parse `1.2` / `1.3` (also `tls1.3`, `TLSv1.3`, case-insensitive).
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let lower = value.trim().to_ascii_lowercase();
        let bare = lower.trim_start_matches("tlsv").trim_start_matches("tls");
        match bare {
            "1.2" => Some(Self::Tls12),
            "1.3" => Some(Self::Tls13),
            _ => None,
        }
    }

    /// The config spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tls12 => "1.2",
            Self::Tls13 => "1.3",
        }
    }
}

/// The cipher-suite profile.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum SuiteProfile {
    /// rustls's AWS-LC defaults: AES-256-GCM, AES-128-GCM (and
    /// ChaCha20-Poly1305 outside `fips`), AES-256 first.
    #[default]
    Default,
    /// AES-256-GCM only (CNSA alignment).
    Aes256Only,
}

impl SuiteProfile {
    /// Parse `default` / `aes256` (case-insensitive).
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "default" => Some(Self::Default),
            "aes256" | "aes-256" | "aes256-only" => Some(Self::Aes256Only),
            _ => None,
        }
    }

    /// The config spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::Aes256Only => "aes256",
        }
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// A TLS policy that cannot be installed as written. Configuration errors
/// name the key, the value and the expected shape, never a silent default.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TlsPolicyError {
    /// A config value did not parse.
    #[error("{key}={value:?} is malformed: expected {expected}")]
    Config {
        /// The config key.
        key: &'static str,
        /// The offending value (escaped; configuration, never a secret).
        value: String,
        /// The expected shape.
        expected: &'static str,
    },
    /// The configuration source itself failed (the lookup's own error,
    /// rendered).
    #[error("reading {key}: {error}")]
    Lookup {
        /// The config key.
        key: &'static str,
        /// The lookup's error.
        error: String,
    },
    /// The group list is empty (after the hybrid-required filter, when on).
    #[error(
        "the TLS policy offers no key-exchange group{}",
        if *.after_hybrid_filter { " once hybrid is required (list a post-quantum group)" } else { "" }
    )]
    NoGroups {
        /// Whether `require_hybrid` emptied the list.
        after_hybrid_filter: bool,
    },
    /// A group is listed twice.
    #[error("key-exchange group {0} is listed twice")]
    DuplicateGroup(KxGroup),
    /// A group the FIPS module does not approve, under the `fips` feature.
    #[error("key-exchange group {0} is not FIPS-approved (refused under the `fips` feature)")]
    NotApproved(KxGroup),
    /// [`install_policy`] ran a second time.
    #[error("a TLS policy is already installed")]
    AlreadyInstalled,
    /// [`install_policy`] ran after the provider was first read: live
    /// configs were already built from the default policy, so a later
    /// policy would describe TLS nothing negotiates. Install it first thing
    /// at boot.
    #[error(
        "the TLS provider was already built from the default policy; install the TLS policy \
         before the first seaworthy_crypto::tls_provider() call"
    )]
    AlreadyFrozen,
}

// ---------------------------------------------------------------------------
// The policy
// ---------------------------------------------------------------------------

/// The process-wide TLS policy. Build with [`TlsPolicy::default`] + the
/// `with_*` methods, or from config ([`TlsPolicy::from_config`]); install
/// with [`install_policy`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TlsPolicy {
    groups: Vec<KxGroup>,
    min_version: MinTlsVersion,
    require_hybrid: bool,
    suites: SuiteProfile,
}

impl Default for TlsPolicy {
    /// The defaults (module docs): this build's default
    /// group list, TLS 1.2 + 1.3, hybrid not required, default suites.
    fn default() -> Self {
        Self {
            groups: default_groups(),
            min_version: MinTlsVersion::Tls12,
            require_hybrid: false,
            suites: SuiteProfile::Default,
        }
    }
}

/// This build's default group list: hybrids first (X25519MLKEM768, what
/// browsers and current servers share, then the P-256 hybrid), then
/// classical; X25519 omitted under `fips`.
#[must_use]
pub fn default_groups() -> Vec<KxGroup> {
    [
        KxGroup::X25519Mlkem768,
        KxGroup::Secp256r1Mlkem768,
        KxGroup::X25519,
        KxGroup::Secp256r1,
        KxGroup::Secp384r1,
    ]
    .into_iter()
    .filter(|group| !cfg!(feature = "fips") || group.approved_under_fips())
    .collect()
}

impl TlsPolicy {
    /// Replace the group list (preference order).
    #[must_use]
    pub fn with_groups(mut self, groups: impl IntoIterator<Item = KxGroup>) -> Self {
        self.groups = groups.into_iter().collect();
        self
    }

    /// Set the minimum protocol version.
    #[must_use]
    pub const fn with_min_version(mut self, min_version: MinTlsVersion) -> Self {
        self.min_version = min_version;
        self
    }

    /// Keep only post-quantum groups (hybrid, or pure ML-KEM when listed).
    #[must_use]
    pub const fn with_require_hybrid(mut self, require: bool) -> Self {
        self.require_hybrid = require;
        self
    }

    /// Set the cipher-suite profile.
    #[must_use]
    pub const fn with_suites(mut self, suites: SuiteProfile) -> Self {
        self.suites = suites;
        self
    }

    /// The configured group list (before the hybrid-required filter).
    #[must_use]
    pub fn groups(&self) -> &[KxGroup] {
        &self.groups
    }

    /// The minimum protocol version.
    #[must_use]
    pub const fn min_version(&self) -> MinTlsVersion {
        self.min_version
    }

    /// Whether only post-quantum groups are offered.
    #[must_use]
    pub const fn requires_hybrid(&self) -> bool {
        self.require_hybrid
    }

    /// The cipher-suite profile.
    #[must_use]
    pub const fn suites(&self) -> SuiteProfile {
        self.suites
    }

    /// The groups the provider offers, in order: the configured list,
    /// narrowed to post-quantum groups when hybrid is required.
    #[must_use]
    pub fn effective_groups(&self) -> Vec<KxGroup> {
        self.groups
            .iter()
            .copied()
            .filter(|group| !self.require_hybrid || group.is_post_quantum())
            .collect()
    }

    /// Check the policy can be enforced as written.
    ///
    /// # Errors
    /// [`TlsPolicyError::DuplicateGroup`], [`TlsPolicyError::NoGroups`],
    /// or — under `fips` — [`TlsPolicyError::NotApproved`].
    pub fn validate(&self) -> Result<(), TlsPolicyError> {
        self.validate_for(cfg!(feature = "fips"))
    }

    /// [`Self::validate`] with the FIPS posture as a parameter (tests).
    fn validate_for(&self, fips: bool) -> Result<(), TlsPolicyError> {
        for (index, group) in self.groups.iter().enumerate() {
            if self
                .groups
                .iter()
                .take(index)
                .any(|earlier| earlier == group)
            {
                return Err(TlsPolicyError::DuplicateGroup(*group));
            }
            if fips && !group.approved_under_fips() {
                return Err(TlsPolicyError::NotApproved(*group));
            }
        }
        if self.groups.is_empty() {
            return Err(TlsPolicyError::NoGroups {
                after_hybrid_filter: false,
            });
        }
        if self.effective_groups().is_empty() {
            return Err(TlsPolicyError::NoGroups {
                after_hybrid_filter: true,
            });
        }
        Ok(())
    }

    /// Read the policy from the published keys ([`BOOTSTRAP_KEYS`])
    /// through `lookup`, typically the process environment, as a
    /// source-bootstrap read (`|key| std::env::var(key)` mapped to
    /// `Option`): the policy must be installed before anything is fetched
    /// over TLS. An absent key keeps its default; a malformed one is a typed
    /// error naming key, value and expected shape. The result is validated.
    ///
    /// # Errors
    /// [`TlsPolicyError::Lookup`] when the source fails,
    /// [`TlsPolicyError::Config`] for a malformed value, and any
    /// [`Self::validate`] error.
    pub fn from_config<E: fmt::Display>(
        mut lookup: impl FnMut(&'static str) -> Result<Option<String>, E>,
    ) -> Result<Self, TlsPolicyError> {
        let mut read = |key: &'static str| {
            lookup(key).map_err(|error| TlsPolicyError::Lookup {
                key,
                error: error.to_string(),
            })
        };
        let mut policy = Self::default();
        if let Some(value) = read(GROUPS_KEY)? {
            let malformed = || TlsPolicyError::Config {
                key: GROUPS_KEY,
                value: value.escape_debug().to_string(),
                expected: "a comma-separated list of X25519MLKEM768, SECP256R1MLKEM768, \
                           X25519, SECP256R1, SECP384R1, MLKEM768, MLKEM1024",
            };
            let mut groups = Vec::new();
            for name in value.split(',') {
                if groups.len() >= MAX_GROUPS * 2 {
                    return Err(malformed());
                }
                groups.push(KxGroup::from_name(name).ok_or_else(malformed)?);
            }
            policy.groups = groups;
        }
        if let Some(value) = read(MIN_VERSION_KEY)? {
            policy.min_version =
                MinTlsVersion::parse(&value).ok_or_else(|| TlsPolicyError::Config {
                    key: MIN_VERSION_KEY,
                    value: value.escape_debug().to_string(),
                    expected: "1.2 or 1.3",
                })?;
        }
        if let Some(value) = read(REQUIRE_HYBRID_KEY)? {
            policy.require_hybrid = match value.trim().to_ascii_lowercase().as_str() {
                "true" => true,
                "false" => false,
                _ => {
                    return Err(TlsPolicyError::Config {
                        key: REQUIRE_HYBRID_KEY,
                        value: value.escape_debug().to_string(),
                        expected: "true or false",
                    });
                }
            };
        }
        if let Some(value) = read(SUITES_KEY)? {
            policy.suites = SuiteProfile::parse(&value).ok_or_else(|| TlsPolicyError::Config {
                key: SUITES_KEY,
                value: value.escape_debug().to_string(),
                expected: "default or aes256",
            })?;
        }
        policy.validate()?;
        Ok(policy)
    }

    /// The provider this policy describes.
    fn build_provider(&self) -> CryptoProvider {
        let base = aws_lc_rs::default_provider();
        let cipher_suites = base
            .cipher_suites
            .iter()
            .copied()
            .filter(|suite| self.min_version == MinTlsVersion::Tls12 || is_tls13(*suite))
            .filter(|suite| self.suites == SuiteProfile::Default || is_aes256(*suite))
            .collect();
        CryptoProvider {
            cipher_suites,
            kx_groups: self
                .effective_groups()
                .into_iter()
                .map(KxGroup::rustls)
                .collect(),
            ..base
        }
    }

    /// One line for boot evidence: `groups=… min=… hybrid=… suites=…`.
    #[must_use]
    pub fn summary(&self) -> String {
        let groups: Vec<&str> = self
            .effective_groups()
            .into_iter()
            .map(KxGroup::name)
            .collect();
        format!(
            "groups={} min_version={} require_hybrid={} suites={}",
            groups.join(","),
            self.min_version.as_str(),
            self.require_hybrid,
            self.suites.as_str()
        )
    }
}

fn is_tls13(suite: SupportedCipherSuite) -> bool {
    matches!(suite, SupportedCipherSuite::Tls13(_))
}

fn is_aes256(suite: SupportedCipherSuite) -> bool {
    matches!(
        suite.suite(),
        CipherSuite::TLS13_AES_256_GCM_SHA384
            | CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            | CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    )
}

// ---------------------------------------------------------------------------
// The installed policy and its providers
// ---------------------------------------------------------------------------

/// The frozen policy and the provider derived from it, built once.
struct Frozen {
    policy: TlsPolicy,
    provider: Arc<CryptoProvider>,
}

static FROZEN: OnceLock<Frozen> = OnceLock::new();
/// Set by [`install_policy`]: tells "installed twice" from "frozen by a
/// read" apart.
static INSTALLED: AtomicBool = AtomicBool::new(false);

fn freeze(policy: TlsPolicy) -> Frozen {
    let provider = Arc::new(policy.build_provider());
    Frozen { policy, provider }
}

fn frozen() -> &'static Frozen {
    FROZEN.get_or_init(|| freeze(TlsPolicy::default()))
}

/// Install the process-wide TLS policy. Call it FIRST at boot, before
/// anything builds a TLS configuration (any [`crate::tls_provider`] read
/// freezes the default policy). Validated before anything is installed.
///
/// # Errors
/// Any [`TlsPolicy::validate`] error; [`TlsPolicyError::AlreadyInstalled`]
/// on a second call; [`TlsPolicyError::AlreadyFrozen`] when the provider
/// was already built from the default policy.
pub fn install_policy(policy: TlsPolicy) -> Result<(), TlsPolicyError> {
    policy.validate()?;
    match FROZEN.set(freeze(policy)) {
        Ok(()) => {
            INSTALLED.store(true, Ordering::SeqCst);
            Ok(())
        }
        Err(_) if INSTALLED.load(Ordering::SeqCst) => Err(TlsPolicyError::AlreadyInstalled),
        Err(_) => Err(TlsPolicyError::AlreadyFrozen),
    }
}

/// The policy in force (the installed one, else the defaults; reading it
/// freezes them).
#[must_use]
pub fn policy() -> &'static TlsPolicy {
    &frozen().policy
}

/// The policy's provider: what [`crate::tls_provider`] returns.
pub(crate) fn provider() -> Arc<CryptoProvider> {
    frozen().provider.clone()
}

/// [`crate::tls_provider`] narrowed to post-quantum groups: the provider a
/// "hybrid required" CLIENT builds on for one connection whatever the
/// process-wide policy says. It refuses, at the handshake, any server that
/// cannot negotiate a hybrid.
///
/// # Errors
/// [`TlsPolicyError::NoGroups`] when the policy lists no post-quantum group.
pub fn post_quantum_provider() -> Result<Arc<CryptoProvider>, TlsPolicyError> {
    let mut provider = (*provider()).clone();
    provider
        .kx_groups
        .retain(|group| is_post_quantum_group(group.name()));
    if provider.kx_groups.is_empty() {
        return Err(TlsPolicyError::NoGroups {
            after_hybrid_filter: true,
        });
    }
    Ok(Arc::new(provider))
}

/// The protocol versions the policy permits, for builders that pass a list
/// explicitly: `[TLS13]` under a 1.3 minimum, else rustls's defaults. (The
/// provider enforces the minimum on its own; see the module docs.)
#[must_use]
pub fn protocol_versions() -> &'static [&'static SupportedProtocolVersion] {
    static TLS13_ONLY: &[&SupportedProtocolVersion] = &[&rustls::version::TLS13];
    match policy().min_version {
        MinTlsVersion::Tls13 => TLS13_ONLY,
        MinTlsVersion::Tls12 => rustls::DEFAULT_VERSIONS,
    }
}

/// A rustls client-config builder on the policy's provider and versions.
///
/// # Errors
/// rustls's own (unreachable for the policies [`TlsPolicy::validate`]
/// admits).
pub fn client_config_builder()
-> Result<rustls::ConfigBuilder<rustls::ClientConfig, rustls::WantsVerifier>, rustls::Error> {
    rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(protocol_versions())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup<'a>(
        pairs: &'a [(&'static str, &'a str)],
    ) -> impl FnMut(&'static str) -> Result<Option<String>, String> + 'a {
        move |key| {
            Ok(pairs
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| (*v).to_owned()))
        }
    }

    #[test]
    fn every_group_round_trips_through_its_name_and_wire_id() {
        for group in KxGroup::ALL {
            assert_eq!(KxGroup::from_name(group.name()), Some(group));
            assert_eq!(KxGroup::from_named_group(group.named_group()), Some(group));
            assert_eq!(group.rustls().name(), group.named_group());
            assert_eq!(
                is_post_quantum_group(group.named_group()),
                group.is_post_quantum()
            );
        }
        assert_eq!(
            KxGroup::from_name("SecP256r1MLKEM768"),
            Some(KxGroup::Secp256r1Mlkem768)
        );
        assert_eq!(KxGroup::from_name("prime256v1"), Some(KxGroup::Secp256r1));
        assert_eq!(KxGroup::from_name("x448"), None);
    }

    #[test]
    fn unknown_post_quantum_codepoints_classify_by_number() {
        // SecP384r1MLKEM1024 (0x11ed) and MLKEM512 (0x0200) are not in
        // rustls 0.23, but a peer negotiating them is post-quantum.
        assert!(is_post_quantum_group(NamedGroup::from(0x11ed)));
        assert!(is_post_quantum_group(NamedGroup::from(0x0200)));
        assert!(!is_post_quantum_group(NamedGroup::secp521r1));
        assert!(!is_post_quantum_group(NamedGroup::X25519));
    }

    #[test]
    fn defaults_put_both_hybrids_first_and_drop_x25519_only_under_fips() {
        let defaults = TlsPolicy::default();
        let expected: &[KxGroup] = if cfg!(feature = "fips") {
            &[
                KxGroup::X25519Mlkem768,
                KxGroup::Secp256r1Mlkem768,
                KxGroup::Secp256r1,
                KxGroup::Secp384r1,
            ]
        } else {
            &[
                KxGroup::X25519Mlkem768,
                KxGroup::Secp256r1Mlkem768,
                KxGroup::X25519,
                KxGroup::Secp256r1,
                KxGroup::Secp384r1,
            ]
        };
        assert_eq!(defaults.groups(), expected);
        assert_eq!(defaults.min_version(), MinTlsVersion::Tls12);
        assert!(!defaults.requires_hybrid());
        assert_eq!(defaults.suites(), SuiteProfile::Default);
        defaults.validate().expect("the defaults validate");
    }

    #[test]
    fn from_config_absent_keys_keep_the_defaults() {
        let policy = TlsPolicy::from_config(lookup(&[])).expect("defaults");
        assert_eq!(policy, TlsPolicy::default());
    }

    #[test]
    fn from_config_reads_every_key() {
        let policy = TlsPolicy::from_config(lookup(&[
            (GROUPS_KEY, " secp256r1mlkem768 , X25519MLKEM768,SECP384R1"),
            (MIN_VERSION_KEY, "TLSv1.3"),
            (REQUIRE_HYBRID_KEY, "true"),
            (SUITES_KEY, "aes256"),
        ]))
        .expect("valid config");
        assert_eq!(
            policy.groups(),
            [
                KxGroup::Secp256r1Mlkem768,
                KxGroup::X25519Mlkem768,
                KxGroup::Secp384r1
            ]
        );
        assert_eq!(
            policy.effective_groups(),
            [KxGroup::Secp256r1Mlkem768, KxGroup::X25519Mlkem768]
        );
        assert_eq!(policy.min_version(), MinTlsVersion::Tls13);
        assert!(policy.requires_hybrid());
        assert_eq!(policy.suites(), SuiteProfile::Aes256Only);
    }

    #[test]
    fn from_config_malformed_values_name_key_value_and_shape() {
        for (key, value) in [
            (GROUPS_KEY, "X25519MLKEM768,brainpool"),
            (GROUPS_KEY, ""),
            (MIN_VERSION_KEY, "1.1"),
            (REQUIRE_HYBRID_KEY, "yes"),
            (SUITES_KEY, "chacha"),
        ] {
            let error = TlsPolicy::from_config(lookup(&[(key, value)])).expect_err(value);
            let TlsPolicyError::Config { key: named, .. } = &error else {
                panic!("{key}={value:?} answered {error:?}");
            };
            assert_eq!(*named, key);
            assert!(error.to_string().contains("expected"), "{error}");
        }
    }

    #[test]
    fn a_failing_source_is_a_typed_lookup_error() {
        let error = TlsPolicy::from_config(|_key| Err::<Option<String>, _>("source down"))
            .expect_err("source failure");
        assert!(
            matches!(
                error,
                TlsPolicyError::Lookup {
                    key: GROUPS_KEY,
                    ..
                }
            ),
            "{error:?}"
        );
    }

    #[test]
    fn validation_refuses_duplicates_empty_lists_and_hybrid_with_no_pq_group() {
        let dup = TlsPolicy::default().with_groups([KxGroup::Secp256r1, KxGroup::Secp256r1]);
        assert_eq!(
            dup.validate_for(false),
            Err(TlsPolicyError::DuplicateGroup(KxGroup::Secp256r1))
        );
        let empty = TlsPolicy::default().with_groups([]);
        assert_eq!(
            empty.validate_for(false),
            Err(TlsPolicyError::NoGroups {
                after_hybrid_filter: false
            })
        );
        let classical_only = TlsPolicy::default()
            .with_groups([KxGroup::Secp256r1])
            .with_require_hybrid(true);
        assert_eq!(
            classical_only.validate_for(false),
            Err(TlsPolicyError::NoGroups {
                after_hybrid_filter: true
            })
        );
    }

    #[test]
    fn fips_validation_refuses_x25519_by_name() {
        let policy = TlsPolicy::default().with_groups([KxGroup::X25519Mlkem768, KxGroup::X25519]);
        assert_eq!(policy.validate_for(false), Ok(()));
        assert_eq!(
            policy.validate_for(true),
            Err(TlsPolicyError::NotApproved(KxGroup::X25519))
        );
    }

    #[test]
    fn the_provider_follows_the_policy_order_exactly() {
        let policy = TlsPolicy::default().with_groups([
            KxGroup::Secp384r1,
            KxGroup::Secp256r1Mlkem768,
            KxGroup::Secp256r1,
        ]);
        let names: Vec<NamedGroup> = policy
            .build_provider()
            .kx_groups
            .iter()
            .map(|group| group.name())
            .collect();
        assert_eq!(
            names,
            [
                NamedGroup::secp384r1,
                NamedGroup::secp256r1MLKEM768,
                NamedGroup::secp256r1
            ]
        );
    }

    #[test]
    fn tls13_minimum_strips_every_tls12_suite() {
        let provider = TlsPolicy::default()
            .with_min_version(MinTlsVersion::Tls13)
            .build_provider();
        assert!(!provider.cipher_suites.is_empty());
        assert!(provider.cipher_suites.iter().all(|suite| is_tls13(*suite)));
    }

    #[test]
    fn aes256_profile_keeps_only_aes256_gcm() {
        let policy = TlsPolicy::default().with_suites(SuiteProfile::Aes256Only);
        let frozen = freeze(policy);
        assert!(!frozen.provider.cipher_suites.is_empty());
        assert!(
            frozen
                .provider
                .cipher_suites
                .iter()
                .all(|suite| is_aes256(*suite))
        );
        assert_eq!(
            frozen.provider.cipher_suites.first().map(|s| s.suite()),
            Some(CipherSuite::TLS13_AES_256_GCM_SHA384)
        );
    }

    #[test]
    fn the_default_profile_puts_aes256_first() {
        let frozen = freeze(TlsPolicy::default());
        let suites: Vec<CipherSuite> = frozen
            .provider
            .cipher_suites
            .iter()
            .map(|s| s.suite())
            .collect();
        assert_eq!(suites.first(), Some(&CipherSuite::TLS13_AES_256_GCM_SHA384));
        assert!(suites.contains(&CipherSuite::TLS13_AES_128_GCM_SHA256));
    }

    #[test]
    fn summary_names_the_effective_policy() {
        let summary = TlsPolicy::default()
            .with_groups([KxGroup::X25519Mlkem768, KxGroup::Secp256r1])
            .with_require_hybrid(true)
            .summary();
        assert_eq!(
            summary,
            "groups=X25519MLKEM768 min_version=1.2 require_hybrid=true suites=default"
        );
    }
}
