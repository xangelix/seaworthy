//! The ML-DSA-87 public-key intake test: refuses keys under which a
//! signature verifies without any secret.
//!
//! FIPS 204 defines no public-key validation, and AWS-LC performs none.
//! Any 2592-byte string `ρ ‖ t1` is a "valid" key to the verifier, which
//! computes `w1' = UseHint(h, A·z − c·t1·2^d)`. With `z = 0` and `h = 0`
//! that is `w1' = HighBits(−c·t1·2^d)`, so whenever that is the zero vector
//! for the challenge `c` the verifier derives, `(c̃ = H(μ ‖ w1Encode(0)),
//! z = 0, h = 0)` verifies over the message: a forger needs only public
//! data. That happens for far more than the all-zero `t1`:
//!
//! - **low weight**: `t1` all zero but one coefficient `1` (each output
//!   coefficient is then `±2^d`, inside the zero bucket);
//! - **structured**: every coefficient `512`: `512·2^d = (q + 8191)/2`, so
//!   two terms sum to `8191` modulo q and a challenge's 60 terms (an even
//!   count) to a multiple of `8191` of magnitude at most `30·8191 < γ2`,
//!   for EVERY challenge, though no coefficient is small;
//! - more generally, any `t1` that makes `c·t1·2^d` land within `±γ2` of
//!   zero in (almost) every coefficient for the challenges a forger can
//!   reach by trying messages. The hint lets a forger repair up to `ω = 75`
//!   coefficients that land just outside.
//!
//! # The test
//!
//! After fast pre-filters (the all-zero `t1`; a polynomial of `t1` with
//! fewer than [`MIN_ROW_WEIGHT`] non-zero coefficients, fewer than
//! [`MIN_DISTINCT`] distinct values, or a period of at most
//! [`MAX_PERIOD`]), the key is MEASURED:
//! for each of [`CHALLENGES`] fixed challenges (SampleInBall's shape:
//! exactly 60 coefficients `±1` at distinct positions, drawn from a
//! SHA-512 stream over a fixed label, so they are reproducible and nothing
//! is up anyone's sleeve) it counts the output coefficients of
//! `HighBits(−c·t1·2^d)` that are NOT zero, per polynomial (256 each) and
//! in total (2048). A forgery needs (nearly) all of them zero; a key is
//! refused when, for any challenge, a polynomial has fewer than
//! [`MIN_ROW_NONZERO`] non-zero coefficients or the total is below
//! [`MIN_TOTAL_NONZERO`].
//!
//! # Calibration and the false-reject bound
//!
//! A genuine key's `t1` is the high part of `A·s1 + s2`, indistinguishable
//! from uniform on `[0, 1023]`. `HighBits(r) = 0` exactly when
//! `r mod q ∈ [0, γ2] ∪ [q − γ2, q − 1]`. An output coefficient is
//! `−2^d·S mod q` for an integer `S` (a signed sum of 60 coefficients of
//! `t1`) whose residue modulo 1024 is uniform, and for each quotient
//! `⌊S/1024⌉` the zero window, `2γ2 + 1` wide, holds the values of at most
//! 64 of the 1024 residues: a coefficient is zero with probability
//! `p ≤ 1/16`. So a polynomial's non-zero count is about
//! `Binomial(256, 15/16)` (mean 240, standard deviation 3.9) and the total
//! about `Binomial(2048, 15/16)` (mean 1920, standard deviation 11). The
//! thresholds sit far below:
//!
//! - a polynomial below 160 non-zero means more than 96 zeros where 16 are
//!   expected; the Chernoff bound `exp(−256·D(97/256 ‖ p))` puts that
//!   below `2^-157` per (challenge, polynomial);
//! - a total below 1664 means more than 384 zeros where 128 are expected:
//!   below `2^-266` per challenge (`exp(−2048·D(385/2048 ‖ p))`).
//!
//! Over all `128 × (8 + 1)` comparisons a genuine key is refused with
//! probability below `2^-147` (the pre-filters add less than `2^-390`).
//! The bound treats coefficients as independent, which they are only
//! approximately (they share `t1`), so it is checked by measurement: the
//! ignored test `intake_false_reject_measurement` runs keys from AWS-LC's
//! key generation through the test. Over 100,000 keys it refused none;
//! the 102.4 million polynomial counts averaged 240.2 (standard deviation
//! 3.85, lowest 215) and the 12.8 million totals 1921.9 (standard
//! deviation 10.9, lowest 1860): the binomial model, with every count 14
//! or more standard deviations above its threshold.
//!
//! # What it does and does not prove
//!
//! It refuses the known forgery classes (all-zero, low-weight, constant,
//! periodic, low-entropy and 2-adically structured `t1`: those whose
//! coefficients times `2^d` sit near multiples of `q/2`) and any key whose
//! forgeability is measurable on typical challenges. A key built so that only a rare
//! set of challenges (one a forger reaches by trying messages) collapses
//! while typical challenges look uniform is not known to exist, but this
//! test cannot rule it out. It is defense in depth, never a substitute for
//! knowing where a key came from.

#![deny(clippy::arithmetic_side_effects)]

use std::sync::OnceLock;

/// q (FIPS 204).
const Q: i64 = 8_380_417;
/// γ2 = (q − 1)/32 for ML-DSA-87.
const GAMMA2: i64 = 261_888;
/// 2^d with d = 13.
const TWO_POW_D: i64 = 8192;
/// Coefficients per polynomial.
const N: usize = 256;
/// k: the polynomials of `t1` for ML-DSA-87.
const K: usize = 8;
/// τ: the non-zero coefficients of a challenge for ML-DSA-87.
const TAU: usize = 60;
/// The seed of `A` that starts a public key; `t1` follows.
const RHO_LEN: usize = 32;
/// One packed `t1` polynomial: 256 coefficients of 10 bits.
const POLY_BYTES: usize = 320;

/// The fixed challenges a key is measured under.
pub(super) const CHALLENGES: usize = 128;
/// A `t1` polynomial with fewer non-zero coefficients is refused (a
/// genuine one has about 255.8; 128 or fewer happens with probability
/// below `2^-1000`).
pub(super) const MIN_ROW_WEIGHT: usize = 128;
/// A `t1` polynomial with fewer distinct coefficient values is refused (a
/// genuine one, 256 draws from 1024 values, has about 226; fewer than 96
/// happens with probability below `C(1024, 95)·(95/1024)^256 < 2^-400`).
/// It catches constant, small-valued and coarsely quantized polynomials
/// (every coefficient a multiple of 128, say) in one pass.
pub(super) const MIN_DISTINCT: usize = 96;
/// A `t1` polynomial that repeats with a period up to this is refused
/// (period 1: a constant polynomial). A genuine one needs at least 128
/// coincidences of probability `2^-10` each.
pub(super) const MAX_PERIOD: usize = 128;
/// Per challenge, a polynomial of `HighBits(−c·t1·2^d)` with fewer
/// non-zero coefficients refuses the key (genuine: 240 ± 3.9).
pub(super) const MIN_ROW_NONZERO: usize = 160;
/// Per challenge, fewer non-zero coefficients over all of
/// `HighBits(−c·t1·2^d)` refuse the key (genuine: 1920 ± 11).
pub(super) const MIN_TOTAL_NONZERO: usize = 1664;

/// The label the challenges are drawn under.
const CHALLENGE_DOMAIN: &[u8] = b"seaworthy-ml-dsa-87-intake:1:challenge";
/// A bound on the bytes one challenge draws (it needs about 70); never
/// reached for the fixed labels, which a test checks.
const MAX_DRAWS: usize = 4096;

/// `t1`: 8 polynomials of 256 coefficients in `[0, 1023]`.
pub(super) type T1 = [[i32; N]; K];

/// Why a key was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Refusal {
    /// Not 2592 bytes.
    Length,
    /// `t1` is all zero.
    ZeroT1,
    /// A polynomial of `t1` has fewer than [`MIN_ROW_WEIGHT`] non-zero
    /// coefficients.
    LowWeight,
    /// A polynomial of `t1` has fewer than [`MIN_DISTINCT`] distinct
    /// values.
    LowEntropy,
    /// A polynomial of `t1` repeats with a period up to [`MAX_PERIOD`].
    Periodic,
    /// Under some challenge, too few coefficients of `HighBits(−c·t1·2^d)`
    /// are non-zero.
    Forgeable,
    /// The fixed challenge set could not be drawn (never, for the fixed
    /// labels; fail closed).
    Challenges,
}

/// One challenge: its 60 non-zero positions and whether each is `−1`.
#[derive(Clone, Copy)]
pub(super) struct Challenge {
    terms: [(u8, bool); TAU],
}

impl Challenge {
    /// The challenge as a dense polynomial (tests, oracles).
    #[cfg(test)]
    pub(super) fn dense(&self) -> [i32; N] {
        let mut c = [0i32; N];
        for &(position, negative) in &self.terms {
            if let Some(slot) = c.get_mut(usize::from(position)) {
                *slot = if negative { -1 } else { 1 };
            }
        }
        c
    }
}

/// The full intake check of a raw public key.
pub(super) fn check(public_key: &[u8]) -> Result<(), Refusal> {
    let t1 = decode_t1(public_key).ok_or(Refusal::Length)?;
    prefilter(&t1)?;
    statistical(&t1)
}

/// `t1` from a raw public key (`ρ ‖ SimpleBitPack(t1, 1023)`: 10-bit
/// coefficients, least significant bit first); `None` unless 2592 bytes.
pub(super) fn decode_t1(public_key: &[u8]) -> Option<T1> {
    if public_key.len() != super::PUBLIC_KEY_LEN {
        return None;
    }
    let (polys, rest) = public_key.get(RHO_LEN..)?.as_chunks::<POLY_BYTES>();
    if polys.len() != K || !rest.is_empty() {
        return None;
    }
    let mut t1 = [[0i32; N]; K];
    for (poly, bytes) in t1.iter_mut().zip(polys) {
        // Four coefficients per five bytes.
        let (slots, _) = poly.as_chunks_mut::<4>();
        let (groups, _) = bytes.as_chunks::<5>();
        for (coefficients, group) in slots.iter_mut().zip(groups) {
            let [b0, b1, b2, b3, b4] = group.map(i32::from);
            *coefficients = [
                b0 | ((b1 & 0x03) << 8),
                (b1 >> 2) | ((b2 & 0x0f) << 6),
                (b2 >> 4) | ((b3 & 0x3f) << 4),
                (b3 >> 6) | (b4 << 2),
            ];
        }
    }
    Some(t1)
}

/// The fast shape checks: all-zero, low-weight, low-entropy and periodic
/// polynomials.
pub(super) fn prefilter(t1: &T1) -> Result<(), Refusal> {
    if t1.iter().flatten().all(|&coefficient| coefficient == 0) {
        return Err(Refusal::ZeroT1);
    }
    for poly in t1 {
        if poly.iter().filter(|&&coefficient| coefficient != 0).count() < MIN_ROW_WEIGHT {
            return Err(Refusal::LowWeight);
        }
        // Coefficients are 10-bit: one flag per value.
        let mut seen = [false; 1024];
        for &coefficient in poly {
            if let Some(flag) = usize::try_from(coefficient)
                .ok()
                .and_then(|value| seen.get_mut(value))
            {
                *flag = true;
            }
        }
        if seen.iter().filter(|&&flag| flag).count() < MIN_DISTINCT {
            return Err(Refusal::LowEntropy);
        }
        let periodic = |period: usize| {
            poly.iter()
                .zip(poly.iter().skip(period))
                .all(|(a, b)| a == b)
        };
        if (1..=MAX_PERIOD).any(periodic) {
            return Err(Refusal::Periodic);
        }
    }
    Ok(())
}

/// The measurement: under every fixed challenge, enough non-zero
/// coefficients of `HighBits(−c·t1·2^d)` per polynomial and in total.
pub(super) fn statistical(t1: &T1) -> Result<(), Refusal> {
    let counts = challenge_counts(t1)?;
    let refused = counts.iter().any(|rows| {
        rows.iter().any(|&count| count < MIN_ROW_NONZERO)
            || rows
                .iter()
                .fold(0usize, |total, &count| total.saturating_add(count))
                < MIN_TOTAL_NONZERO
    });
    if refused {
        Err(Refusal::Forgeable)
    } else {
        Ok(())
    }
}

/// For each fixed challenge, the non-zero coefficients of
/// `HighBits(−c·t1·2^d)` in each of the 8 polynomials.
pub(super) fn challenge_counts(t1: &T1) -> Result<Vec<[usize; K]>, Refusal> {
    let challenges = challenges().ok_or(Refusal::Challenges)?;
    // Each polynomial extended negacyclically: `ext[256 + i] = t[i]` and
    // `ext[i] = −t[i]`, so `X^j·t` (in Z[X]/(X^256 + 1)) is the window
    // `ext[256 − j .. 512 − j]`.
    let mut extended = [[0i32; 2 * N]; K];
    for (ext, poly) in extended.iter_mut().zip(t1) {
        let (negated, plain) = ext.split_at_mut(N);
        for ((low, high), &coefficient) in negated.iter_mut().zip(plain.iter_mut()).zip(poly) {
            *low = coefficient.wrapping_neg();
            *high = coefficient;
        }
    }
    let mut out = Vec::with_capacity(challenges.len());
    for challenge in challenges {
        let mut rows = [0usize; K];
        for (count, ext) in rows.iter_mut().zip(&extended) {
            // `S = c·t` over the integers (|S| ≤ 60·1023: no overflow).
            let mut sum = [0i32; N];
            for &(position, negative) in &challenge.terms {
                let start = N.wrapping_sub(usize::from(position));
                let Some(window) = ext.get(start..start.wrapping_add(N)) else {
                    return Err(Refusal::Challenges);
                };
                if negative {
                    for (s, &v) in sum.iter_mut().zip(window) {
                        *s = s.wrapping_sub(v);
                    }
                } else {
                    for (s, &v) in sum.iter_mut().zip(window) {
                        *s = s.wrapping_add(v);
                    }
                }
            }
            *count = sum.iter().filter(|&&s| high_bits_nonzero(s)).count();
        }
        out.push(rows);
    }
    Ok(out)
}

/// Whether `HighBits(−S·2^d mod q)` is non-zero: FIPS 204's Decompose
/// returns `r1 = 0` exactly for `r mod q` in `[0, γ2] ∪ [q − γ2, q − 1]`.
pub(super) fn high_bits_nonzero(sum: i32) -> bool {
    let r = i64::from(sum)
        .wrapping_neg()
        .wrapping_mul(TWO_POW_D)
        .wrapping_rem_euclid(Q);
    r > GAMMA2 && r < Q.wrapping_sub(GAMMA2)
}

/// The fixed challenges, drawn once per process.
pub(super) fn challenges() -> Option<&'static [Challenge]> {
    static SET: OnceLock<Option<Vec<Challenge>>> = OnceLock::new();
    SET.get_or_init(|| {
        (0..CHALLENGES)
            .map(|index| u16::try_from(index).ok().and_then(sample_in_ball))
            .collect()
    })
    .as_deref()
}

/// A SHA-512 counter-mode byte stream under [`CHALLENGE_DOMAIN`] and a
/// challenge index.
struct Stream {
    index: u16,
    counter: u32,
    block: [u8; 64],
    used: usize,
}

impl Stream {
    fn new(index: u16) -> Self {
        Self {
            index,
            counter: 0,
            block: [0; 64],
            used: 64,
        }
    }

    fn next(&mut self) -> u8 {
        if self.used >= self.block.len() {
            let mut input = CHALLENGE_DOMAIN.to_vec();
            input.extend_from_slice(&self.index.to_be_bytes());
            input.extend_from_slice(&self.counter.to_be_bytes());
            self.block = crate::digest::sha512(&input);
            self.counter = self.counter.wrapping_add(1);
            self.used = 0;
        }
        let byte = self.block.get(self.used).copied().unwrap_or(0);
        self.used = self.used.wrapping_add(1);
        byte
    }
}

/// FIPS 204's SampleInBall (Algorithm 29) over [`Stream`] instead of
/// SHAKE-256: 8 bytes of signs, then for `i` from `256 − τ` to 255 a
/// rejection-sampled `j ≤ i`, `c[i] = c[j]`, `c[j] = ±1`.
fn sample_in_ball(index: u16) -> Option<Challenge> {
    let mut stream = Stream::new(index);
    let mut sign_bytes = [0u8; 8];
    for byte in &mut sign_bytes {
        *byte = stream.next();
    }
    let signs = u64::from_le_bytes(sign_bytes);
    let mut c = [0i8; N];
    let mut draws = 0usize;
    for (sign_bit, i) in (N.wrapping_sub(TAU)..N).enumerate() {
        let j = loop {
            if draws >= MAX_DRAWS {
                return None;
            }
            draws = draws.wrapping_add(1);
            let j = usize::from(stream.next());
            if j <= i {
                break j;
            }
        };
        let moved = c.get(j).copied()?;
        *c.get_mut(i)? = moved;
        *c.get_mut(j)? = if (signs >> sign_bit) & 1 == 1 { -1 } else { 1 };
    }
    let mut terms = [(0u8, false); TAU];
    let mut slots = terms.iter_mut();
    for (position, &value) in c.iter().enumerate() {
        if value != 0 {
            *slots.next()? = (u8::try_from(position).ok()?, value < 0);
        }
    }
    // Exactly τ non-zero coefficients, or the draw is not a challenge.
    slots.next().is_none().then_some(Challenge { terms })
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, reason = "test arithmetic")]
mod tests;
