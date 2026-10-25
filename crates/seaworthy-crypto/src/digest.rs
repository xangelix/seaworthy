//! Digests, from AWS-LC (the AWS-LC FIPS 4.2.0 module under `fips`).
//! One-shot by design, plus the streaming [`Sha256`]/[`Sha512`] contexts for
//! callers hashing data in flight (the publisher hashes objects while
//! streaming them; the update helper verifies downloaded artifacts in
//! fixed-size chunks instead of holding them whole in memory).

/// SHA-256 over `data`.
#[allow(
    clippy::expect_used,
    reason = "the algorithm fixes the output length; the conversion cannot fail"
)]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data)
        .as_ref()
        .try_into()
        .expect("SHA-256 output is 32 bytes")
}

/// An incremental SHA-256 context: `update` per chunk, `finish` once.
/// Byte-for-byte equivalent to [`sha256`] over the concatenation.
pub struct Sha256(aws_lc_rs::digest::Context);

impl Sha256 {
    /// A fresh context.
    #[must_use]
    pub fn new() -> Self {
        Self(aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256))
    }

    /// Absorb a chunk.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// The digest of everything absorbed so far (consumes the context).
    #[must_use]
    #[allow(
        clippy::expect_used,
        reason = "the algorithm fixes the output length; the conversion cannot fail"
    )]
    pub fn finish(self) -> [u8; 32] {
        self.0
            .finish()
            .as_ref()
            .try_into()
            .expect("SHA-256 output is 32 bytes")
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

/// SHA-256 over `data`, hex-encoded (for hashes used as identifiers).
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(sha256(data))
}

/// SHA-512 over `data`.
#[allow(
    clippy::expect_used,
    reason = "the algorithm fixes the output length; the conversion cannot fail"
)]
pub fn sha512(data: &[u8]) -> [u8; 64] {
    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA512, data)
        .as_ref()
        .try_into()
        .expect("SHA-512 output is 64 bytes")
}

/// An incremental SHA-512 context: `update` per chunk, `finish` once.
/// Byte-for-byte equivalent to [`sha512`] over the concatenation (the
/// [`Sha256`] shape, for the artifacts the update helper hashes in chunks).
pub struct Sha512(aws_lc_rs::digest::Context);

impl Sha512 {
    /// A fresh context.
    #[must_use]
    pub fn new() -> Self {
        Self(aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA512))
    }

    /// Absorb a chunk.
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    /// The digest of everything absorbed so far (consumes the context).
    #[must_use]
    #[allow(
        clippy::expect_used,
        reason = "the algorithm fixes the output length; the conversion cannot fail"
    )]
    pub fn finish(self) -> [u8; 64] {
        self.0
            .finish()
            .as_ref()
            .try_into()
            .expect("SHA-512 output is 64 bytes")
    }
}

impl Default for Sha512 {
    fn default() -> Self {
        Self::new()
    }
}

/// SHA-512 over `data`, hex-encoded (for hashes used as identifiers).
pub fn sha512_hex(data: &[u8]) -> String {
    hex::encode(sha512(data))
}

/// SHA-1 over `data`, **only for identifiers whose definition fixes
/// SHA-1**. It gives no integrity, authenticity or collision resistance:
/// SHA-1 collisions are practical, so never use it for anything an
/// attacker could choose input to.
///
/// The one caller is the Windows virtual-account SID. Windows derives
/// `NT SERVICE\<name>`'s SID as `S-1-5-80-` followed by the SHA-1 of the
/// upper-cased service name, so the Windows service renderer can compute it
/// at packaging time, before the service exists. The input is a service
/// name the product itself chose.
///
/// SHA-1 stays an approved hash for non-signature uses in the AWS-LC FIPS
/// module (NIST SP 800-131A Rev. 2), so this works in `fips` builds too.
/// NIST plans to retire SHA-1 entirely after 2030 (the SP 800-131A Rev. 3
/// draft); Windows' SID definition will outlive that, so the computation
/// may then need its own implementation outside the FIPS boundary.
///
/// The workspace `clippy.toml` disallows this function everywhere but its
/// reasoned call sites.
#[allow(
    clippy::expect_used,
    reason = "the algorithm fixes the output length; the conversion cannot fail"
)]
pub fn sha1_for_identifiers(data: &[u8]) -> [u8; 20] {
    aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA1_FOR_LEGACY_USE_ONLY, data)
        .as_ref()
        .try_into()
        .expect("SHA-1 output is 20 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(
        clippy::disallowed_methods,
        reason = "the function's own known-answer test"
    )]
    fn sha1_known_answers() {
        // FIPS 180-4's "abc" and the empty string.
        assert_eq!(
            hex::encode(sha1_for_identifiers(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex::encode(sha1_for_identifiers(b"")),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
    }

    #[test]
    fn sha256_known_answer() {
        // The classic empty-string vector, and "abc" from FIPS 180-4.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sha512_known_answer() {
        // The classic empty-string vector, and "abc" from FIPS 180-4.
        assert_eq!(
            sha512_hex(b""),
            "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce\
             47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        );
        assert_eq!(
            sha512_hex(b"abc"),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }

    #[test]
    fn sha512_output_shape() {
        // The golden boundary: 64 raw bytes, 128 lowercase hex chars —
        // callers (e.g. the release manifests, whose `sha512:` digest the
        // update helper compares with the package it streams)
        // validate against exactly these lengths.
        assert_eq!(sha512(b"boundary").len(), 64);
        let hex = sha512_hex(b"boundary");
        assert_eq!(hex.len(), 128);
        assert!(
            hex.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
    }

    #[test]
    fn streaming_sha256_matches_one_shot() {
        let mut ctx = Sha256::new();
        ctx.update(b"ba");
        ctx.update(b"7816bf8f01cfea414140de5dae2223".as_slice());
        ctx.update(b""); // an empty update is a no-op
        ctx.update(b"c");
        let one_shot = sha256(b"ba7816bf8f01cfea414140de5dae2223c");
        assert_eq!(ctx.finish(), one_shot);
        assert_eq!(Sha256::new().finish(), sha256(b""), "empty stream");
        assert_eq!(Sha256::default().finish(), sha256(b""));
    }

    #[test]
    fn streaming_sha512_matches_one_shot() {
        let mut ctx = Sha512::new();
        ctx.update(b"dd");
        ctx.update(b"af35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a".as_slice());
        ctx.update(b""); // an empty update is a no-op
        ctx.update(b"0");
        let one_shot = sha512(b"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a0");
        assert_eq!(ctx.finish(), one_shot);
        assert_eq!(Sha512::new().finish(), sha512(b""), "empty stream");
        assert_eq!(Sha512::default().finish(), sha512(b""));
    }

    #[test]
    fn streaming_sha512_matches_one_shot_at_odd_chunk_boundaries() {
        // A larger input (2 KiB + 3, deliberately NOT a chunk multiple)
        // fed through several odd chunk sizes — including one byte at a
        // time and past the SHA-512 128-byte block boundary — must land on
        // the one-shot digest byte-for-byte.
        let input: Vec<u8> = (0..(2048 + 3)).map(|i| (i % 251) as u8).collect();
        let one_shot = sha512(&input);
        for chunk_size in [1_usize, 3, 127, 128, 129, 1024, 2048] {
            let mut ctx = Sha512::new();
            for chunk in input.chunks(chunk_size) {
                ctx.update(chunk);
            }
            assert_eq!(
                ctx.finish(),
                one_shot,
                "chunked hashing at chunk size {chunk_size} diverged from one-shot"
            );
        }
    }
}
