//! `mldsa_public_key` — the ML-DSA-87 public-key intake test
//! (`seaworthy_crypto::mldsa::validate_public_key`), which every release
//! key (`seaworthy_formats::ReleaseKey::new`) and every ML-DSA-87
//! verification runs. A uniformly random key is never forgeable, so
//! besides raw bytes the target builds STRUCTURED keys, the shapes the
//! known keyless forgeries use: periodic and constant `t1` polynomials,
//! scaled (2-adically coarse) values, sparse ones over a background, and
//! generated keys with rows overwritten.
//!
//! Input: `[mode][bytes]`.
//!
//! Invariants:
//! - no panic, for any length;
//! - the verdict is deterministic;
//! - a key the intake test ACCEPTS never verifies the keyless forgery
//!   (`c̃ = H(μ ‖ w1Encode(0))`, `z = 0`, `h = 0`): `verify` answers
//!   `InvalidSignature` for it (a crash here is a forgeable key that
//!   passed intake), and `InvalidKey` for a refused key.

use seaworthy_crypto::CryptoError;
use seaworthy_crypto::mldsa::{PUBLIC_KEY_LEN, SigningKey, validate_public_key, verify};

#[allow(dead_code, reason = "the shared helper has more than this target uses")]
#[path = "../../../crates/seaworthy-crypto/tests/support/keyless_forgery.rs"]
mod keyless_forgery;

/// `t1`: 8 polynomials of 256 coefficients.
type T1 = [[u16; 256]; 8];

/// Runs one input (see the module docs for its layout).
pub fn run(data: &[u8]) {
    let Some((&mode, bytes)) = data.split_first() else {
        return;
    };
    let key = match mode % 4 {
        0 => bytes.to_vec(),
        1 => periodic(bytes),
        2 => sparse(bytes),
        _ => edited(bytes),
    };
    check(&key);
}

fn check(key: &[u8]) {
    let verdict = validate_public_key(key).is_ok();
    assert_eq!(verdict, validate_public_key(key).is_ok(), "nondeterministic verdict");
    if key.len() != PUBLIC_KEY_LEN {
        assert!(!verdict, "a {}-byte key was accepted", key.len());
        return;
    }
    let message = b"seaworthy fuzz: keyless forgery";
    let forged = keyless_forgery::keyless_forgery(key, message);
    match verify(key, message, &forged) {
        Err(CryptoError::InvalidSignature) => assert!(verdict, "a refused key reached the verifier"),
        Err(CryptoError::InvalidKey) => assert!(!verdict, "an accepted key was refused by verify"),
        Ok(()) => panic!("a key the intake test accepts verifies a keyless forgery"),
        Err(other) => panic!("unexpected error {other:?}"),
    }
}

fn pack(t1: &T1) -> Vec<u8> {
    let mut rho = [0u8; 32];
    rho[0] = 0x5a;
    keyless_forgery::pack_public_key(rho, t1)
}

/// 10-bit values from byte pairs.
fn values(bytes: &[u8]) -> Vec<u16> {
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair) & 0x3ff)
        .collect()
}

/// `[shift][row period][pattern…]`: a pattern of 10-bit values repeated
/// over every polynomial (with the polynomial index added, so rows differ
/// when the pattern says so), each value multiplied by `2^shift` mod 1024:
/// constant, periodic and coarsely quantized `t1`.
fn periodic(bytes: &[u8]) -> Vec<u8> {
    let [shift, row_offset, rest @ ..] = bytes else {
        return Vec::new();
    };
    let pattern = values(rest);
    if pattern.is_empty() {
        return pack(&[[512; 256]; 8]);
    }
    let shift = u32::from(shift % 10);
    let t1: T1 = std::array::from_fn(|row| {
        std::array::from_fn(|i| {
            let value = pattern[(i + row * usize::from(*row_offset)) % pattern.len()];
            (value << shift) & 0x3ff
        })
    });
    pack(&t1)
}

/// `[background: 2][entries: (index: 2, value: 2)…]`: a background value
/// with point edits (index over all 2048 coefficients).
fn sparse(bytes: &[u8]) -> Vec<u8> {
    let Some((background, entries)) = bytes.split_first_chunk::<2>() else {
        return Vec::new();
    };
    let mut t1: T1 = [[u16::from_le_bytes(*background) & 0x3ff; 256]; 8];
    for entry in entries.as_chunks::<4>().0 {
        let index = usize::from(u16::from_le_bytes([entry[0], entry[1]]) & 0x7ff);
        t1[index / 256][index % 256] = u16::from_le_bytes([entry[2], entry[3]]) & 0x3ff;
    }
    pack(&t1)
}

/// `[seed: 32][edits: (row, kind, a, b)…]`: a generated key with whole
/// polynomials overwritten (constant `a`, `a`/`b` alternating, the row
/// scaled by `2^a`, or zeroed).
fn edited(bytes: &[u8]) -> Vec<u8> {
    let Some((seed, edits)) = bytes.split_first_chunk::<32>() else {
        return Vec::new();
    };
    let Ok(signing) = SigningKey::from_seed(seed) else {
        return Vec::new();
    };
    let key = signing.public_key();
    let mut t1: T1 = [[0; 256]; 8];
    for (row, poly) in t1.iter_mut().enumerate() {
        for (i, c) in poly.iter_mut().enumerate() {
            let bit = 32 * 8 + (row * 256 + i) * 10;
            let word = u32::from_le_bytes([
                key[bit / 8],
                key[bit / 8 + 1],
                key.get(bit / 8 + 2).copied().unwrap_or(0),
                0,
            ]);
            *c = u16::try_from((word >> (bit % 8)) & 0x3ff).unwrap();
        }
    }
    for edit in edits.as_chunks::<4>().0 {
        let row = usize::from(edit[0] % 8);
        let (a, b) = (u16::from(edit[2]) << 2, u16::from(edit[3]) << 2);
        let poly = &mut t1[row];
        match edit[1] % 4 {
            0 => poly.fill(a),
            1 => poly.iter_mut().enumerate().for_each(|(i, c)| *c = if i % 2 == 0 { a } else { b }),
            2 => poly.iter_mut().for_each(|c| *c = (*c << (edit[2] % 10)) & 0x3ff),
            _ => poly.fill(0),
        }
    }
    let rho: [u8; 32] = key[..32].try_into().unwrap();
    keyless_forgery::pack_public_key(rho, &t1)
}
