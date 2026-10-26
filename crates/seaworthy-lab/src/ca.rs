//! The lab's throwaway CA: one root and one leaf for the lab's host names,
//! for the TLS lanes, which put the root in the machine's trust store,
//! point the names at the loopback and run the lab server with the leaf.
//!
//! Three properties keep a trusted throwaway root from being more than
//! the lane needs:
//!
//! - **Name constraints.** The root's critical `nameConstraints` permit
//!   exactly the leaf's DNS names (and their subdomains): a certificate it
//!   signed for any other host fails validation. Those names must be under
//!   `.invalid` or `.test` (RFC 6761), which never resolve publicly.
//! - **No root key after generation.** The root's private key lives in
//!   memory for the two signatures (root and leaf) and is dropped; it is
//!   never written, so nothing can issue another certificate under the
//!   root the machine trusts.
//! - **A short life.** Both certificates are valid from an hour ago (clock
//!   skew) for the requested days (2 by default, at most 30).
//!
//! Keys are ECDSA P-256 and signatures ECDSA with SHA-256, all through
//! seaworthy-crypto; rcgen only encodes the certificates. The root's
//! subject names the run (`seaworthy lab CA <random>`), so a root a lane
//! failed to remove is told apart from the next one.

use std::path::Path;
use std::time::Duration;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose,
    GeneralSubtree, IsCa, Issuer, KeyIdMethod, KeyUsagePurpose, NameConstraints, PublicKeyData,
    SerialNumber, SignatureAlgorithm, SigningKey,
};
use zeroize::Zeroizing;

use crate::LabError;

/// The default validity of the lab's certificates.
pub const DEFAULT_VALIDITY: Duration = Duration::from_secs(2 * 24 * 3600);

/// The longest validity [`LabCa::generate`] accepts.
pub const MAX_VALIDITY: Duration = Duration::from_secs(30 * 24 * 3600);

/// The most names one leaf carries.
pub const MAX_NAMES: usize = 16;

/// The DER prefix of every P-256 `SubjectPublicKeyInfo` (the
/// id-ecPublicKey and prime256v1 OIDs, then the BIT STRING header); the
/// uncompressed point follows.
const P256_SPKI_PREFIX: [u8; 26] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
];

/// A generated root and leaf, PEM-encoded.
pub struct LabCa {
    ca_pem: String,
    leaf_pem: String,
    leaf_key_pem: Zeroizing<String>,
    names: Vec<String>,
}

impl std::fmt::Debug for LabCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LabCa")
            .field("names", &self.names)
            .finish_non_exhaustive()
    }
}

/// A seaworthy-crypto ECDSA P-256 key as rcgen's signer.
struct EcdsaKey {
    key: seaworthy_crypto::ecdsa::SigningKey,
    spki: Vec<u8>,
    point: Vec<u8>,
}

impl EcdsaKey {
    fn generate() -> Result<(Self, Zeroizing<Vec<u8>>), LabError> {
        let (key, pkcs8) = seaworthy_crypto::ecdsa::SigningKey::generate_pkcs8()
            .map_err(|e| LabError::Crypto(format!("generating a P-256 key: {e}")))?;
        let spki = key.public_key_der();
        let point = spki
            .strip_prefix(&P256_SPKI_PREFIX[..])
            .filter(|point| point.len() == 65 && point.first() == Some(&0x04))
            .ok_or_else(|| LabError::Crypto("an unexpected P-256 public key encoding".to_owned()))?
            .to_vec();
        Ok((Self { key, spki, point }, pkcs8))
    }

    /// RFC 7093 method 1: the leftmost 160 bits of the SHA-256 of the
    /// `SubjectPublicKeyInfo`.
    fn key_id(&self) -> Vec<u8> {
        seaworthy_crypto::digest::sha256(&self.spki)
            .get(..20)
            .map(<[u8]>::to_vec)
            .unwrap_or_default()
    }
}

impl PublicKeyData for EcdsaKey {
    fn der_bytes(&self) -> &[u8] {
        &self.point
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

impl SigningKey for EcdsaKey {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        self.key
            .sign(message)
            .map_err(|_| rcgen::Error::RemoteKeyError)
    }
}

/// A positive 128-bit serial number from the RNG.
fn serial() -> Result<SerialNumber, LabError> {
    let mut bytes = [0_u8; 16];
    seaworthy_crypto::rand::fill(&mut bytes)
        .map_err(|e| LabError::Crypto(format!("serial number: {e}")))?;
    if let Some(first) = bytes.first_mut() {
        *first = (*first & 0x7f) | 0x40;
    }
    Ok(SerialNumber::from_slice(&bytes))
}

/// The top-level domains the lab certifies names under: RFC 6761's
/// `.invalid` and `.test`, which never resolve on the public internet, so
/// a root the machine trusts for the run can't vouch for a real host even
/// within its name constraints.
const LAB_DOMAINS: [&str; 2] = ["invalid", "test"];

/// A DNS name the lab certifies: lowercase letters, digits, `-` and `.`,
/// labels of 1-63 characters, at most 253 in all, at least two labels, no
/// wildcard, under one of [`LAB_DOMAINS`].
fn check_name(name: &str) -> Result<(), LabError> {
    let labels_ok = name.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    });
    if name.len() > 253 || !name.contains('.') || !labels_ok {
        return Err(LabError::Invalid(format!(
            "{name:?} is not a DNS name the lab certifies (lowercase labels of a-z 0-9 -, at least two)"
        )));
    }
    let reserved = name
        .rsplit('.')
        .next()
        .is_some_and(|top| LAB_DOMAINS.contains(&top));
    if !reserved {
        return Err(LabError::Invalid(format!(
            "{name:?} is not under .invalid or .test: the lab certifies only names that never resolve publicly"
        )));
    }
    Ok(())
}

/// Base64 PEM of one DER object.
fn pem(label: &str, der: &[u8]) -> String {
    use base64::Engine as _;
    let body = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    let mut rest = body.as_str();
    while !rest.is_empty() {
        let (line, tail) = rest.split_at(rest.len().min(64));
        out.push_str(line);
        out.push('\n');
        rest = tail;
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

impl LabCa {
    /// A root constrained to `names` and a leaf for them (the first is its
    /// common name), valid for `validity`.
    ///
    /// # Errors
    /// [`LabError::Invalid`] for no names, more than [`MAX_NAMES`], a name
    /// that isn't a plain DNS name, or a validity outside one day to
    /// [`MAX_VALIDITY`]; [`LabError::Crypto`] when a key, a serial or a
    /// signature can't be made.
    pub fn generate(names: &[String], validity: Duration) -> Result<Self, LabError> {
        if names.is_empty() || names.len() > MAX_NAMES {
            return Err(LabError::Invalid(format!(
                "the lab certifies 1-{MAX_NAMES} names"
            )));
        }
        for name in names {
            check_name(name)?;
        }
        if validity < Duration::from_secs(24 * 3600) || validity > MAX_VALIDITY {
            return Err(LabError::Invalid(
                "the lab's certificates are valid for 1-30 days".to_owned(),
            ));
        }
        let now = time::OffsetDateTime::now_utc();
        let not_before = now - time::Duration::hours(1);
        let not_after = now
            + time::Duration::try_from(validity)
                .map_err(|e| LabError::Invalid(format!("validity: {e}")))?;

        // The root: its key exists only in this function.
        let (root_key, _root_pkcs8) = EcdsaKey::generate()?;
        let mut tag = [0_u8; 4];
        seaworthy_crypto::rand::fill(&mut tag)
            .map_err(|e| LabError::Crypto(format!("the root's name: {e}")))?;
        let tag: String = tag.iter().map(|byte| format!("{byte:02x}")).collect();
        let mut root = CertificateParams::default();
        let mut root_name = DistinguishedName::new();
        root_name.push(DnType::CommonName, format!("seaworthy lab CA {tag}"));
        root.distinguished_name = root_name;
        root.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        root.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        root.name_constraints = Some(NameConstraints {
            permitted_subtrees: names
                .iter()
                .map(|name| GeneralSubtree::DnsName(name.clone()))
                .collect(),
            excluded_subtrees: Vec::new(),
        });
        root.not_before = not_before;
        root.not_after = not_after;
        root.serial_number = Some(serial()?);
        root.key_identifier_method = KeyIdMethod::PreSpecified(root_key.key_id());
        let root_cert = root
            .self_signed(&root_key)
            .map_err(|e| LabError::Crypto(format!("signing the root: {e}")))?;

        // The leaf, signed by the root.
        let (leaf_key, leaf_pkcs8) = EcdsaKey::generate()?;
        let mut leaf = CertificateParams::new(names.to_vec())
            .map_err(|e| LabError::Invalid(format!("the leaf's names: {e}")))?;
        let mut leaf_name = DistinguishedName::new();
        leaf_name.push(
            DnType::CommonName,
            names.first().cloned().unwrap_or_default(),
        );
        leaf.distinguished_name = leaf_name;
        leaf.is_ca = IsCa::ExplicitNoCa;
        leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        leaf.not_before = not_before;
        leaf.not_after = not_after;
        leaf.serial_number = Some(serial()?);
        leaf.key_identifier_method = KeyIdMethod::PreSpecified(leaf_key.key_id());
        leaf.use_authority_key_identifier_extension = true;
        let issuer = Issuer::from_params(&root, &root_key);
        let leaf_cert = leaf
            .signed_by(&leaf_key, &issuer)
            .map_err(|e| LabError::Crypto(format!("signing the leaf: {e}")))?;

        Ok(Self {
            ca_pem: pem("CERTIFICATE", root_cert.der()),
            leaf_pem: pem("CERTIFICATE", leaf_cert.der()),
            leaf_key_pem: Zeroizing::new(pem("PRIVATE KEY", &leaf_pkcs8)),
            names: names.to_vec(),
        })
    }

    /// The root certificate (PEM): what the machine trusts.
    #[must_use]
    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    /// The leaf certificate (PEM): the lab server's chain.
    #[must_use]
    pub fn leaf_pem(&self) -> &str {
        &self.leaf_pem
    }

    /// The leaf's private key (PKCS#8 PEM): the lab server's key.
    #[must_use]
    pub fn leaf_key_pem(&self) -> &str {
        &self.leaf_key_pem
    }

    /// The names the leaf carries (and the root permits).
    #[must_use]
    pub fn names(&self) -> &[String] {
        &self.names
    }

    /// Writes `ca.pem`, `leaf.pem` and `leaf.key` (owner-only on unix) into
    /// `dir`, each a new file.
    ///
    /// # Errors
    /// [`LabError::Io`] when `dir` can't be made or a file exists already
    /// or can't be written.
    pub fn write(&self, dir: &Path) -> Result<(), LabError> {
        std::fs::create_dir_all(dir).map_err(|e| LabError::io(dir.display(), e))?;
        write_new(&dir.join("ca.pem"), self.ca_pem.as_bytes(), false)?;
        write_new(&dir.join("leaf.pem"), self.leaf_pem.as_bytes(), false)?;
        write_new(&dir.join("leaf.key"), self.leaf_key_pem.as_bytes(), true)
    }
}

/// A new file holding `bytes`: owner-only (0600) on unix when `private`.
fn write_new(path: &Path, bytes: &[u8], private: bool) -> Result<(), LabError> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(if private { 0o600 } else { 0o644 });
    }
    #[cfg(not(unix))]
    let _ = private;
    let mut file = options
        .open(path)
        .map_err(|e| LabError::io(path.display(), e))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|e| LabError::io(path.display(), e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names() -> Vec<String> {
        vec![
            "packages.lab.invalid".to_owned(),
            "updates.lab.invalid".to_owned(),
        ]
    }

    #[test]
    fn names_are_checked() {
        for bad in [
            "",
            "localhost",
            "*.lab.invalid",
            "Lab.invalid",
            "a..b",
            "-a.b",
            "a_b.c",
            // Real names, however lab-like: never certified.
            "packages.example.com",
            "lab.internal",
            "invalid.example",
            "test.invalid.com",
            "lab.testing",
        ] {
            assert!(
                LabCa::generate(&[bad.to_owned()], DEFAULT_VALIDITY).is_err(),
                "{bad:?}"
            );
        }
        for good in ["lab.invalid", "packages.lab.invalid", "updates.lab.test"] {
            assert!(
                LabCa::generate(&[good.to_owned()], DEFAULT_VALIDITY).is_ok(),
                "{good:?}"
            );
        }
        assert!(LabCa::generate(&[], DEFAULT_VALIDITY).is_err());
        assert!(LabCa::generate(&names(), Duration::from_secs(60)).is_err());
        assert!(LabCa::generate(&names(), MAX_VALIDITY + Duration::from_secs(1)).is_err());
    }

    #[test]
    fn pem_wraps_at_64_columns() {
        let text = pem("CERTIFICATE", &[0xab; 100]);
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.first(), Some(&"-----BEGIN CERTIFICATE-----"));
        assert_eq!(lines.last(), Some(&"-----END CERTIFICATE-----"));
        assert!(lines.iter().all(|line| line.len() <= 64));
        assert_eq!(lines.len(), 5);
    }

    /// The DER inside a PEM file.
    fn der(pem: &str) -> Vec<u8> {
        use base64::Engine as _;
        let body: String = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        base64::engine::general_purpose::STANDARD
            .decode(body)
            .unwrap()
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    #[test]
    fn the_root_is_name_constrained_and_the_leaf_a_server_certificate() {
        let ca = LabCa::generate(&names(), DEFAULT_VALIDITY).unwrap();
        let (root, leaf) = (der(ca.ca_pem()), der(ca.leaf_pem()));
        // id-ce-nameConstraints (2.5.29.30), and each permitted name.
        assert!(contains(&root, &[0x06, 0x03, 0x55, 0x1d, 0x1e]));
        for name in names() {
            assert!(
                contains(&root, name.as_bytes()),
                "{name} in the constraints"
            );
            assert!(contains(&leaf, name.as_bytes()), "{name} in the leaf");
        }
        // id-kp-serverAuth (1.3.6.1.5.5.7.3.1) in the leaf, not the root.
        let server_auth = [0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
        assert!(contains(&leaf, &server_auth));
        assert!(!contains(&root, &server_auth));
        // Every run's root is another.
        let again = LabCa::generate(&names(), DEFAULT_VALIDITY).unwrap();
        assert_ne!(again.ca_pem(), ca.ca_pem());
    }

    #[test]
    fn writes_three_new_files_the_key_private() {
        let ca = LabCa::generate(&names(), DEFAULT_VALIDITY).unwrap();
        assert!(ca.ca_pem().starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(
            ca.leaf_key_pem()
                .starts_with("-----BEGIN PRIVATE KEY-----\n")
        );
        let dir = tempfile::tempdir().unwrap();
        ca.write(dir.path()).unwrap();
        for name in ["ca.pem", "leaf.pem", "leaf.key"] {
            assert!(dir.path().join(name).is_file(), "{name}");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(dir.path().join("leaf.key"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // Never over an existing file.
        assert!(ca.write(dir.path()).is_err());
    }
}
