//! A signed release manifest's statement re-signed by a throwaway key: the
//! lanes' "another key" case. The statement is byte for byte the original
//! (product, channel, version, build, sequence, target, format, size and
//! digest all genuine), so a helper that refuses it refuses the key, never
//! a damaged statement. The key is ML-DSA-87, the lanes' algorithm,
//! generated here and dropped: nothing can sign with it again.

use seaworthy_formats::{ManifestSignature, ReleaseManifest, SignatureAlgorithm, release_key_id};

use crate::LabError;

/// `signed` (a `.manifest` file) with its signatures replaced by one from
/// a fresh ML-DSA-87 key that no build trusts.
///
/// # Errors
/// [`LabError::Invalid`] when `signed` isn't a signed release manifest, or
/// is signed with another algorithm than ML-DSA-87; [`LabError::Crypto`]
/// when the key can't be generated.
pub fn resign_with_throwaway_key(signed: &[u8]) -> Result<Vec<u8>, LabError> {
    let (manifest, signatures) = ReleaseManifest::decode_signed(signed)
        .map_err(|e| LabError::Invalid(format!("not a signed release manifest: {e}")))?;
    if signatures
        .iter()
        .any(|signature| signature.algorithm != SignatureAlgorithm::MlDsa87)
    {
        return Err(LabError::Invalid(
            "the manifest carries a signature other than ML-DSA-87 (the lanes sign with ML-DSA-87 alone)"
                .to_owned(),
        ));
    }
    let statement = manifest
        .statement()
        .map_err(|e| LabError::Invalid(format!("the manifest's statement: {e}")))?;
    let key = seaworthy_crypto::mldsa::SigningKey::generate()
        .map_err(|e| LabError::Crypto(e.to_string()))?;
    let key_id = release_key_id(SignatureAlgorithm::MlDsa87, &key.public_key());
    if signatures
        .iter()
        .any(|signature| signature.key_id == key_id)
    {
        return Err(LabError::Crypto(
            "the throwaway key has a trusted key's id".to_owned(),
        ));
    }
    let signature = ManifestSignature {
        algorithm: SignatureAlgorithm::MlDsa87,
        key_id,
        signature: key.sign(&statement).to_vec(),
    };
    manifest
        .encode_signed(&[signature])
        .map_err(|e| LabError::Invalid(format!("re-encoding the manifest: {e}")))
}

#[cfg(test)]
mod tests {
    use seaworthy_formats::{ArtifactFormat, DigestAlgorithm, ManifestTrust, ReleaseKey};

    use super::*;

    fn manifest() -> ReleaseManifest {
        ReleaseManifest {
            product: "acme-agent".to_owned(),
            channel: Some("stable".to_owned()),
            version: "1.0.0".to_owned(),
            build: "g0123456789ab".to_owned(),
            sequence: 7,
            target: "x86_64-unknown-linux-gnu".to_owned(),
            format: ArtifactFormat::Deb,
            size: 4,
            digest_algorithm: DigestAlgorithm::Sha256,
            digest: vec![7; 32],
        }
    }

    #[test]
    fn the_statement_survives_and_only_the_key_changes() {
        let trusted = seaworthy_crypto::mldsa::SigningKey::generate().unwrap();
        let statement = manifest().statement().unwrap();
        let signed = manifest()
            .encode_signed(&[ManifestSignature {
                algorithm: SignatureAlgorithm::MlDsa87,
                key_id: release_key_id(SignatureAlgorithm::MlDsa87, &trusted.public_key()),
                signature: trusted.sign(&statement).to_vec(),
            }])
            .unwrap();
        let foreign = resign_with_throwaway_key(&signed).unwrap();
        let (original, first) = ReleaseManifest::decode_signed(&signed).unwrap();
        let (resigned, second) = ReleaseManifest::decode_signed(&foreign).unwrap();
        assert_eq!(resigned, original);
        assert_eq!(second.len(), 1);
        assert_ne!(second[0].key_id, first[0].key_id);

        // The trusted key verifies the original and refuses the copy.
        let key =
            ReleaseKey::new(trusted.public_key().to_vec(), SignatureAlgorithm::MlDsa87).unwrap();
        let trust = ManifestTrust::new("acme-agent", [key])
            .unwrap()
            .channel("stable")
            .unwrap();
        let token = "1.0.0+g0123456789ab";
        assert!(trust.verify(&signed, token, ArtifactFormat::Deb).is_ok());
        assert!(trust.verify(&foreign, token, ArtifactFormat::Deb).is_err());
    }

    #[test]
    fn garbage_is_refused() {
        assert!(matches!(
            resign_with_throwaway_key(b"not a manifest"),
            Err(LabError::Invalid(_))
        ));
    }
}
