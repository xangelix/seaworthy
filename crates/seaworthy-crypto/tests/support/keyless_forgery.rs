//! Test support: SHAKE-256 (FIPS 202) and ML-DSA-87's keyless forgery.
//!
//! Under a public key `pk`, the signature `c̃ ‖ BitPack(z = 0) ‖
//! HintBitPack(h = 0)` with `c̃ = H(μ ‖ w1Encode(0))`, `μ = H(H(pk) ‖ 0 ‖ 0
//! ‖ message)` (pure ML-DSA, empty context) needs no secret. It verifies
//! exactly when `HighBits(−c·t1·2^d) = 0` for the challenge `c` that `c̃`
//! derives, which `seaworthy_crypto::mldsa::validate_public_key` exists to
//! refuse. Shared by the crypto tests and the repository's fuzz crate
//! (`fuzz/src/targets/mldsa_public_key.rs`); a test-only SHAKE, so the
//! workspace keeps one cryptography stack.

/// The Keccak-f\[1600\] round constants.
const ROUND_CONSTANTS: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// The rho rotation offsets, lane `x + 5y`.
const ROTATIONS: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

/// SHAKE-256's rate in bytes.
const RATE: usize = 136;

fn keccak_f(state: &mut [u64; 25]) {
    for round_constant in ROUND_CONSTANTS {
        let mut parity = [0u64; 5];
        for (x, p) in parity.iter_mut().enumerate() {
            *p = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        for x in 0..5 {
            let d = parity[(x + 4) % 5] ^ parity[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                state[x + 5 * y] ^= d;
            }
        }
        let mut moved = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                moved[y + 5 * ((2 * x + 3 * y) % 5)] =
                    state[x + 5 * y].rotate_left(ROTATIONS[x + 5 * y]);
            }
        }
        for x in 0..5 {
            for y in 0..5 {
                state[x + 5 * y] =
                    moved[x + 5 * y] ^ (!moved[(x + 1) % 5 + 5 * y] & moved[(x + 2) % 5 + 5 * y]);
            }
        }
        state[0] ^= round_constant;
    }
}

/// SHAKE-256 over the concatenation of `parts`, `out_len` bytes.
pub(crate) fn shake256(parts: &[&[u8]], out_len: usize) -> Vec<u8> {
    let mut message: Vec<u8> = parts.concat();
    // Padding: the SHAKE domain bits, then pad10*1.
    message.push(0x1f);
    while !message.len().is_multiple_of(RATE) {
        message.push(0);
    }
    let last = message.len() - 1;
    message[last] |= 0x80;
    let mut state = [0u64; 25];
    for block in message.as_chunks::<RATE>().0 {
        for (lane, bytes) in state.iter_mut().zip(block.as_chunks::<8>().0) {
            *lane ^= u64::from_le_bytes(*bytes);
        }
        keccak_f(&mut state);
    }
    let mut out = Vec::with_capacity(out_len);
    loop {
        for lane in &state[..RATE / 8] {
            for byte in lane.to_le_bytes() {
                if out.len() == out_len {
                    return out;
                }
                out.push(byte);
            }
        }
        keccak_f(&mut state);
    }
}

/// The ML-DSA-87 signature length.
const SIGNATURE_LEN: usize = 4627;

/// The keyless forgery over `message` (pure ML-DSA-87, empty context)
/// under `public_key`: `c̃ ‖ BitPack(0) ‖ HintBitPack(0)`.
pub(crate) fn keyless_forgery(public_key: &[u8], message: &[u8]) -> Vec<u8> {
    let tr = shake256(&[public_key], 64);
    let mu = shake256(&[&tr, &[0, 0], message], 64);
    let mut signature = shake256(&[&mu, &[0u8; 1024]], 64);
    // z = 0: each 20-bit coefficient packs as γ1 − 0 = 2^19, two per
    // 5-byte group.
    for _ in 0..(7 * 640 / 5) {
        signature.extend_from_slice(&[0x00, 0x00, 0x08, 0x00, 0x80]);
    }
    // h = 0: ω + k = 83 zero bytes.
    signature.extend_from_slice(&[0u8; 83]);
    assert_eq!(signature.len(), SIGNATURE_LEN);
    signature
}

/// `ρ ‖ SimpleBitPack(t1, 1023)` from 8 polynomials of 256 coefficients
/// in `[0, 1023]`.
pub(crate) fn pack_public_key(rho: [u8; 32], t1: &[[u16; 256]; 8]) -> Vec<u8> {
    let mut key = rho.to_vec();
    for poly in t1 {
        for group in poly.as_chunks::<4>().0 {
            assert!(group.iter().all(|&c| c < 1024));
            let [a, b, c, d] = group.map(u64::from);
            let bits = a | (b << 10) | (c << 20) | (d << 30);
            key.extend_from_slice(&bits.to_le_bytes()[..5]);
        }
    }
    assert_eq!(key.len(), 2592);
    key
}
