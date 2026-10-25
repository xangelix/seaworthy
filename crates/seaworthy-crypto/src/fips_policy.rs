//! The algorithm-admission policy: what `seaworthy-crypto/fips`, and the
//! deployment's installed [`AlgorithmPolicy`], let through at an intake
//! point.
//!
//! **The `fips` feature means *only approved services are reachable*,** not
//! merely "the FIPS module is linked". Every intake point that admits an
//! algorithm choice (a release-key install, a manifest signature check)
//! calls [`ensure_approved`]; under `fips` a non-approved service is refused
//! there with [`CryptoError::NotApproved`] naming it, never silently served.
//! Every signature service this crate offers today is approved by the
//! linked module; the one refusal is HMAC under a key below 112 bits
//! ([`Service::HmacShortKey`], consulted by [`crate::hmac`]). The gate
//! exists so that a future non-approved algorithm is refused where it
//! enters.
//!
//! **The deployment's policy:** the same gate then consults the process's
//! installed [`AlgorithmPolicy`], with two explicit axes:
//!
//! - **which signature algorithms** an intake point may admit
//!   ([`SignatureSet`]; [`AlgorithmPolicy::DEFAULT`] admits every one the
//!   facade offers; [`AlgorithmPolicy::ML_DSA_87_ONLY`] is the
//!   post-quantum-only preset), and
//! - **which reading of "approved"** applies ([`Posture`]):
//!   [`Posture::ApprovedInLinkedModule`] (the default) admits what the
//!   LINKED module's service indicator marks approved;
//!   [`Posture::CertifiedOnly`] admits only what a CMVP certificate that is
//!   VALIDATED today lists ([`Service::certified`]).
//!
//! A refusal is [`CryptoError::NotAllowed`] naming the service and why.
//! Install the policy once, first thing at boot ([`install_policy`]);
//! installing after any intake point consulted it, or twice, is a typed
//! [`PolicyInstallError`]: one configured authority, never a silent swap.
//!
//! # The evidence behind the tables ([`Service::approved`], [`Service::certified`])
//!
//! Primary sources, read 2026-09-28 (re-checked 2026-10-06):
//!
//! - **CMVP certificates #5314 (static) / #5298 (dynamic)**: "AWS-LC 3
//!   Cryptographic Module", Active (validated June 2026). The #5314
//!   security policy (v1.2, 2026-05-20) lists **EDDSA KeyGen / SigGen /
//!   SigVer, Curve ED-25519, FIPS 186-5** in Table 5 ("Approved
//!   Algorithms"), and "Key Generation / Signature Generation / Signature
//!   Verification with EDDSA" in Table 12 ("Approved Services"); EdDSA
//!   appears in neither non-approved table. ECDSA P-256 and SHA-2 are
//!   approved there too. **ML-DSA is NOT on #5314/#5298.**
//!   <https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5314>
//! - **AWS-LC FIPS 4.2.0**, the module this crate LINKS under `fips`
//!   (`aws-lc-fips-sys` 0.14.2, pinned; [`crate::module`] asserts the
//!   version): "AWS-LC 4 Cryptographic Module" is on the CMVP *Modules In
//!   Process* list (Comment Resolution since 2026-09-29), no certificate
//!   yet. Its service indicator
//!   (`crypto/fipsmodule/service_indicator/service_indicator.c`) marks
//!   Ed25519 sign/verify/keygen AND ML-DSA approved; `aws-lc-rs`'s own FIPS
//!   tests assert `Approved` for Ed25519.
//!
//! So Ed25519 IS an approved service, and every service the build runs,
//! ML-DSA-87 included, runs in the 4.2.0 module, whose certificate is in
//! process. The default posture admits what that module's indicator
//! approves (the design assumes AWS-LC FIPS 4.2.0 will be validated;
//! FedRAMP rev 5 SC-13 permits in-process modules with a POA&M); a
//! deployment whose contract demands "certified today" installs
//! [`AlgorithmPolicy::CERTIFIED_ONLY`], which refuses ML-DSA-87 at every
//! intake point that consults this gate.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::CryptoError;

/// A cryptographic service an intake point admits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Service {
    /// Ed25519 (EdDSA, FIPS 186-5) key generation / signing / verification.
    Ed25519,
    /// ECDSA P-256 with SHA-256 (FIPS 186-5).
    EcdsaP256,
    /// ML-DSA-87 (FIPS 204): approved by the linked 4.2.0 module's
    /// indicator; not on a validated certificate yet (see the module docs).
    MlDsa87,
    /// HMAC under a key below 112 bits: neither approved nor listed (the
    /// AWS-LC Security Policies' HMAC key length is 112–524288 bits).
    /// [`crate::hmac`] consults it only for a short key.
    HmacShortKey,
}

/// A CMVP module record the tables cite ("approved by the linked module's
/// indicator" and "listed on a validated certificate" are different facts).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Module {
    /// AWS-LC 3 Cryptographic Module: VALIDATED, certificates #5314
    /// (static) / #5298 (dynamic). Not the module this crate links.
    AwsLc3,
    /// AWS-LC FIPS 4.2.0: the LINKED module (CMVP: in process, Comment
    /// Resolution).
    AwsLcFips4,
}

impl Module {
    /// The module's name as the records spell it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::AwsLc3 => "AWS-LC 3 Cryptographic Module",
            Self::AwsLcFips4 => "AWS-LC FIPS 4.2.0",
        }
    }

    /// The CMVP status, as of the date in the module docs.
    #[must_use]
    pub const fn cmvp_status(self) -> &'static str {
        match self {
            Self::AwsLc3 => "validated, certificates #5314 (static) / #5298 (dynamic)",
            Self::AwsLcFips4 => "in process (Comment Resolution), no certificate yet",
        }
    }

    /// Whether the module holds a validated certificate today.
    #[must_use]
    pub const fn validated(self) -> bool {
        match self {
            Self::AwsLc3 => true,
            Self::AwsLcFips4 => false,
        }
    }
}

impl Service {
    /// The human-readable name errors carry.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ed25519 => "Ed25519 (EdDSA)",
            Self::EcdsaP256 => "ECDSA P-256/SHA-256",
            Self::MlDsa87 => "ML-DSA-87",
            Self::HmacShortKey => "HMAC with a key below 112 bits",
        }
    }

    /// Whether the LINKED module (AWS-LC FIPS 4.2.0) offers this as an
    /// APPROVED service per its service indicator: the
    /// [`Posture::ApprovedInLinkedModule`] reading. Says nothing about
    /// certification ([`Self::certified`]).
    #[must_use]
    pub const fn approved(self) -> bool {
        match self {
            Self::Ed25519 | Self::EcdsaP256 | Self::MlDsa87 => true,
            Self::HmacShortKey => false,
        }
    }

    /// The module records that list this service as approved (the CMVP
    /// security-policy tables the module docs cite).
    #[must_use]
    pub const fn listed_in(self) -> &'static [Module] {
        match self {
            Self::Ed25519 | Self::EcdsaP256 => &[Module::AwsLc3, Module::AwsLcFips4],
            Self::MlDsa87 => &[Module::AwsLcFips4],
            Self::HmacShortKey => &[],
        }
    }

    /// Whether a module with a VALIDATED certificate today lists this
    /// service as approved: the [`Posture::CertifiedOnly`] reading.
    /// ML-DSA-87 is not (#5314/#5298 lack it).
    #[must_use]
    pub const fn certified(self) -> bool {
        // A slice-pattern walk: `const`, and no index that could panic.
        let mut modules = self.listed_in();
        while let [module, rest @ ..] = modules {
            if module.validated() {
                return true;
            }
            modules = rest;
        }
        false
    }

    /// Whether this is a signature service ([`SignatureSet`] constrains
    /// only these).
    #[must_use]
    pub const fn is_signature(self) -> bool {
        matches!(self, Self::Ed25519 | Self::EcdsaP256 | Self::MlDsa87)
    }

    /// The bit a [`SignatureSet`] keeps for a signature service.
    const fn signature_bit(self) -> u8 {
        match self {
            Self::MlDsa87 => 1,
            Self::Ed25519 => 1 << 1,
            Self::EcdsaP256 => 1 << 2,
            Self::HmacShortKey => 0,
        }
    }
}

/// Which reading of "approved" the intake points apply.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Posture {
    /// Admit what the LINKED module's service indicator marks approved
    /// (AWS-LC FIPS 4.2.0, CMVP in process): the default.
    ApprovedInLinkedModule,
    /// Admit only what a module with a VALIDATED certificate lists today
    /// (AWS-LC 3, #5314/#5298): refuses ML-DSA-87. For a contract that
    /// demands "certified today"; the services still run in the linked
    /// 4.2.0 module (pinning the 3.x module is a separate build decision).
    CertifiedOnly,
}

/// A set of signature algorithms an intake point may admit (non-signature
/// services pass untouched). The intake point's own supported set further
/// narrows it.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct SignatureSet(u8);

impl SignatureSet {
    /// Every signature algorithm the facade offers (ML-DSA-87, Ed25519,
    /// ECDSA P-256).
    pub const ALL: Self = Self(0b111);
    /// ML-DSA-87 only: the post-quantum preset.
    pub const ML_DSA_87_ONLY: Self = Self(0b001);

    /// The empty set (refuses every signature algorithm; build up with
    /// [`with`](Self::with)).
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// This set plus `service` (a non-signature service is ignored).
    #[must_use]
    pub const fn with(self, service: Service) -> Self {
        Self(self.0 | service.signature_bit())
    }

    /// Whether `service` is in the set (`false` for a non-signature
    /// service; ask [`AlgorithmPolicy::admits`] instead).
    #[must_use]
    pub const fn contains(self, service: Service) -> bool {
        let bit = service.signature_bit();
        bit != 0 && self.0 & bit == bit
    }
}

impl std::fmt::Debug for SignatureSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = [Service::MlDsa87, Service::Ed25519, Service::EcdsaP256]
            .into_iter()
            .filter(|service| self.contains(*service))
            .map(Service::name)
            .collect();
        f.debug_set().entries(names).finish()
    }
}

/// The deployment's algorithm-admission policy: both axes, explicit
/// (module docs). Install it once at boot with [`install_policy`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AlgorithmPolicy {
    /// Which reading of "approved" applies.
    pub posture: Posture,
    /// Which signature algorithms intake points may admit.
    pub signatures: SignatureSet,
}

impl AlgorithmPolicy {
    /// The linked module's indicator and every signature algorithm the
    /// facade offers. What an application gets without an install.
    pub const DEFAULT: Self = Self {
        posture: Posture::ApprovedInLinkedModule,
        signatures: SignatureSet::ALL,
    };
    /// ML-DSA-87 is the only signature algorithm admitted (release keys,
    /// manifest signatures): the post-quantum-only preset.
    pub const ML_DSA_87_ONLY: Self = Self {
        posture: Posture::ApprovedInLinkedModule,
        signatures: SignatureSet::ML_DSA_87_ONLY,
    };
    /// Only services a VALIDATED certificate lists today (the strict
    /// posture): refuses ML-DSA-87, so a post-quantum intake point refuses
    /// to start under it, loudly.
    pub const CERTIFIED_ONLY: Self = Self {
        posture: Posture::CertifiedOnly,
        signatures: SignatureSet::ALL,
    };

    /// Whether this policy admits `service` (the FIPS-feature half is
    /// [`ensure_approved_for`]'s; this is the deployment half).
    ///
    /// # Errors
    /// [`CryptoError::NotAllowed`] naming the service and the axis that
    /// refused it.
    pub fn admits(&self, service: Service) -> Result<(), CryptoError> {
        if self.posture == Posture::CertifiedOnly && !service.certified() {
            return Err(CryptoError::NotAllowed {
                service: service.name(),
                reason: "not listed on a CMVP certificate validated today (certified-only posture)",
            });
        }
        if service.is_signature() && !self.signatures.contains(service) {
            return Err(CryptoError::NotAllowed {
                service: service.name(),
                reason: "not in the deployment's allowed signature algorithms",
            });
        }
        Ok(())
    }
}

impl Default for AlgorithmPolicy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Why [`install_policy`] refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PolicyInstallError {
    /// A policy is already installed (install once, at boot).
    #[error("an algorithm policy is already installed (install once, at boot)")]
    AlreadySet,
    /// An intake point already consulted the policy (and got the default):
    /// install it FIRST thing at boot, before any key intake.
    #[error(
        "the algorithm policy was already consulted (the default applied); install it first \
         thing at boot, before any key intake"
    )]
    AlreadyRead,
}

static POLICY: OnceLock<AlgorithmPolicy> = OnceLock::new();
static POLICY_READ: AtomicBool = AtomicBool::new(false);

/// Install the process's [`AlgorithmPolicy`]: once, first thing at boot
/// (before any key intake consults it).
///
/// # Errors
/// [`PolicyInstallError::AlreadyRead`] when an intake point already
/// consulted the (default) policy; [`PolicyInstallError::AlreadySet`] on a
/// second install.
pub fn install_policy(policy: AlgorithmPolicy) -> Result<(), PolicyInstallError> {
    if POLICY_READ.load(Ordering::SeqCst) {
        return Err(PolicyInstallError::AlreadyRead);
    }
    POLICY
        .set(policy)
        .map_err(|_| PolicyInstallError::AlreadySet)
}

/// The process's policy: the installed one, else
/// [`AlgorithmPolicy::DEFAULT`]. Reading it freezes the answer (a later
/// [`install_policy`] is refused).
#[must_use]
pub fn policy() -> AlgorithmPolicy {
    POLICY_READ.store(true, Ordering::SeqCst);
    POLICY.get().copied().unwrap_or_default()
}

/// Is this build's `fips` feature on (the "approved services only"
/// posture)? The compile-time half; [`crate::is_fips`] is the runtime
/// answer about the module and the TLS provider.
#[must_use]
pub const fn approved_only() -> bool {
    cfg!(feature = "fips")
}

/// THE intake gate. Admit `service`: under the `fips` feature a
/// non-approved service is refused ([`CryptoError::NotApproved`]); then the
/// installed [`AlgorithmPolicy`] must admit it ([`CryptoError::NotAllowed`]:
/// a signature algorithm outside the deployment's set, or an uncertified
/// service under [`Posture::CertifiedOnly`]). Without the feature and
/// without an install, everything the facade offers passes (the default).
///
/// # Errors
/// [`CryptoError::NotApproved`] or [`CryptoError::NotAllowed`], naming the
/// service.
pub fn ensure_approved(service: Service) -> Result<(), CryptoError> {
    ensure_admitted_by(service, approved_only(), &policy())
}

/// [`ensure_approved`] with both halves explicit: the pure form every
/// build profile can test.
///
/// # Errors
/// As [`ensure_approved`].
pub fn ensure_admitted_by(
    service: Service,
    approved_only: bool,
    policy: &AlgorithmPolicy,
) -> Result<(), CryptoError> {
    ensure_approved_for(service, approved_only)?;
    policy.admits(service)
}

/// The FIPS-feature half alone, with the posture explicit, so both arms
/// are exercised in every build profile (the gate is `cfg!`-fed at the real
/// call site).
///
/// # Errors
/// [`CryptoError::NotApproved`] when `approved_only` and the service is
/// not approved.
pub fn ensure_approved_for(service: Service, approved_only: bool) -> Result<(), CryptoError> {
    if approved_only && !service.approved() {
        return Err(CryptoError::NotApproved(service.name()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every signature service (HMAC's short-key refusal has its own test).
    const ALL_SERVICES: [Service; 3] = [Service::Ed25519, Service::EcdsaP256, Service::MlDsa87];

    /// HMAC under a key below 112 bits is neither approved nor listed
    /// (#5314 Table 5: HMAC key length 112–524288), so `fips` refuses it
    /// and so does the certified-only posture; it is not a signature
    /// service, so a signature set never admits or refuses it.
    #[test]
    fn a_short_hmac_key_is_neither_approved_nor_certified() {
        let short = Service::HmacShortKey;
        assert!(!short.approved());
        assert!(!short.certified());
        assert!(!short.is_signature());
        assert!(!SignatureSet::ALL.contains(short));
        assert!(short.name().contains("112"));
        assert!(matches!(
            ensure_approved_for(short, true),
            Err(CryptoError::NotApproved(_))
        ));
        assert!(ensure_approved_for(short, false).is_ok());
        assert!(AlgorithmPolicy::DEFAULT.admits(short).is_ok());
        assert!(AlgorithmPolicy::ML_DSA_87_ONLY.admits(short).is_ok());
        assert!(matches!(
            AlgorithmPolicy::CERTIFIED_ONLY.admits(short),
            Err(CryptoError::NotAllowed { .. })
        ));
    }

    /// The research conclusion, pinned: every signature service the facade
    /// offers is approved by the linked module's indicator (Ed25519
    /// included: CMVP #5314 Table 12), so the feature half admits all of
    /// them.
    #[test]
    fn approved_table_matches_the_cmvp_record() {
        for service in ALL_SERVICES {
            assert!(service.approved(), "{service:?}");
            assert!(ensure_approved_for(service, true).is_ok());
            assert!(ensure_approved_for(service, false).is_ok());
            assert!(service.is_signature(), "{service:?}");
        }
    }

    /// "Certified" is its own fact. #5314/#5298 list EdDSA and ECDSA, NOT
    /// ML-DSA; the linked 4.2.0 module holds no certificate yet.
    #[test]
    fn certified_table_matches_the_validated_certificates() {
        assert!(Module::AwsLc3.validated());
        assert!(!Module::AwsLcFips4.validated());
        for service in [Service::Ed25519, Service::EcdsaP256] {
            assert!(service.certified(), "{service:?} is on #5314");
        }
        assert!(
            !Service::MlDsa87.certified(),
            "ML-DSA is not on #5314/#5298"
        );
        assert!(
            Service::MlDsa87.approved(),
            "…but the 4.2.0 indicator approves it"
        );
        // Every certified service is also approved by the linked module.
        for service in ALL_SERVICES {
            if service.certified() {
                assert!(service.approved(), "{service:?}");
            }
        }
        assert!(!Module::AwsLcFips4.cmvp_status().is_empty());
        assert_eq!(Module::AwsLcFips4.name(), "AWS-LC FIPS 4.2.0");
    }

    /// The default policy admits everything the feature half admits: the
    /// behavior for applications that install nothing.
    #[test]
    fn the_default_policy_changes_nothing() {
        for service in ALL_SERVICES {
            for approved_only in [false, true] {
                assert_eq!(
                    ensure_admitted_by(service, approved_only, &AlgorithmPolicy::DEFAULT).is_ok(),
                    ensure_approved_for(service, approved_only).is_ok(),
                    "{service:?} approved_only={approved_only}"
                );
            }
        }
    }

    #[test]
    fn ml_dsa_87_only_refuses_every_other_signature() {
        let policy = AlgorithmPolicy::ML_DSA_87_ONLY;
        assert!(policy.admits(Service::MlDsa87).is_ok());
        for refused in [Service::Ed25519, Service::EcdsaP256] {
            let err = policy.admits(refused).expect_err("refused");
            assert!(
                matches!(err, CryptoError::NotAllowed { service, reason }
                    if service == refused.name() && reason.contains("signature")),
                "{err}"
            );
            // The same refusal through the full gate, in both postures.
            for approved_only in [false, true] {
                assert!(matches!(
                    ensure_admitted_by(refused, approved_only, &policy),
                    Err(CryptoError::NotAllowed { .. })
                ));
            }
        }
    }

    #[test]
    fn certified_only_refuses_ml_dsa_and_names_the_posture() {
        let policy = AlgorithmPolicy::CERTIFIED_ONLY;
        let err = policy.admits(Service::MlDsa87).expect_err("not certified");
        assert!(
            matches!(err, CryptoError::NotAllowed { service: "ML-DSA-87", reason }
                if reason.contains("certified-only")),
            "{err}"
        );
        for passes in [Service::Ed25519, Service::EcdsaP256] {
            assert!(policy.admits(passes).is_ok(), "{passes:?}");
        }
    }

    #[test]
    fn signature_sets_compose() {
        let set = SignatureSet::empty().with(Service::Ed25519);
        assert!(set.contains(Service::Ed25519));
        assert!(!set.contains(Service::MlDsa87));
        assert!(!SignatureSet::empty().contains(Service::Ed25519));
        assert_eq!(
            SignatureSet::empty()
                .with(Service::MlDsa87)
                .with(Service::Ed25519)
                .with(Service::EcdsaP256),
            SignatureSet::ALL
        );
        assert_eq!(
            format!("{:?}", SignatureSet::ML_DSA_87_ONLY),
            "{\"ML-DSA-87\"}"
        );
    }

    #[test]
    fn the_compile_time_posture_follows_the_feature() {
        assert_eq!(approved_only(), cfg!(feature = "fips"));
        for service in ALL_SERVICES {
            assert!(ensure_approved_for(service, approved_only()).is_ok());
        }
    }
}
