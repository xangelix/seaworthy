//! The intake test's own tests: decoding, the challenge set, the fast
//! measurement against a literal FIPS 204 oracle, genuine keys passing and
//! structured keys refused (the end-to-end forgeries, verified by AWS-LC,
//! are in `tests/mldsa.rs`).

use super::*;
use crate::mldsa::{PUBLIC_KEY_LEN, SEED_LEN, SigningKey};

/// `ρ ‖ SimpleBitPack(t1, 1023)`.
fn pack(rho: [u8; RHO_LEN], t1: &T1) -> Vec<u8> {
    let mut key = rho.to_vec();
    for poly in t1 {
        for group in poly.as_chunks::<4>().0 {
            let v = group.map(|c| u32::try_from(c).unwrap());
            assert!(v.iter().all(|&c| c < 1024));
            let bits = v[0] | (v[1] << 10) | (v[2] << 20) | ((v[3] & 0x3) << 30);
            key.extend_from_slice(&bits.to_le_bytes());
            key.push(u8::try_from(v[3] >> 2).unwrap());
        }
    }
    assert_eq!(key.len(), PUBLIC_KEY_LEN);
    key
}

fn genuine(seed: u64) -> Vec<u8> {
    let mut bytes = [0u8; SEED_LEN];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    bytes[8..16].copy_from_slice(b"intake-t");
    SigningKey::from_seed(&bytes).unwrap().public_key().to_vec()
}

fn t1_from(mut f: impl FnMut(usize, usize) -> i32) -> T1 {
    let mut t1 = [[0i32; N]; K];
    for (row, poly) in t1.iter_mut().enumerate() {
        for (i, c) in poly.iter_mut().enumerate() {
            *c = f(row, i);
        }
    }
    t1
}

/// A deterministic, non-cryptographic generator for test keys.
struct SplitMix(u64);

impl SplitMix {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn coefficient(&mut self) -> i32 {
        i32::try_from(self.next() % 1024).unwrap()
    }
}

// ---------- FIPS 204, literally: the oracle ----------

/// Decompose's `r1` (FIPS 204, Algorithm 36).
fn decompose_r1(r: i64) -> i64 {
    let r_plus = r.rem_euclid(Q);
    let mut r0 = r_plus.rem_euclid(2 * GAMMA2);
    if r0 > GAMMA2 {
        r0 -= 2 * GAMMA2;
    }
    if r_plus - r0 == Q - 1 {
        0
    } else {
        (r_plus - r0) / (2 * GAMMA2)
    }
}

/// `HighBits(−c·t·2^d)` non-zero count, by dense schoolbook multiplication
/// in Z_q[X]/(X^256 + 1).
fn oracle_count(c: &[i32; N], t: &[i32; N]) -> usize {
    let mut product = [0i64; N];
    for (i, &ci) in c.iter().enumerate() {
        for (j, &tj) in t.iter().enumerate() {
            let term = (i64::from(ci) * i64::from(tj) * TWO_POW_D).rem_euclid(Q);
            if i + j < N {
                product[i + j] = (product[i + j] + term) % Q;
            } else {
                product[i + j - N] = (product[i + j - N] - term).rem_euclid(Q);
            }
        }
    }
    product.iter().filter(|&&r| decompose_r1(-r) != 0).count()
}

#[test]
fn high_bits_matches_decompose_everywhere_it_matters() {
    // Every S a challenge can produce (|S| ≤ 60·1023).
    for s in -61_380..=61_380 {
        assert_eq!(
            high_bits_nonzero(s),
            decompose_r1(-i64::from(s) * TWO_POW_D) != 0,
            "S = {s}"
        );
    }
    // The window edges themselves.
    for r in [
        0,
        1,
        GAMMA2 - 1,
        GAMMA2,
        GAMMA2 + 1,
        Q - GAMMA2 - 1,
        Q - GAMMA2,
        Q - 1,
    ] {
        let expected_zero = r <= GAMMA2 || r >= Q - GAMMA2;
        assert_eq!(decompose_r1(r) == 0, expected_zero, "r = {r}");
    }
}

#[test]
fn decoding_inverts_packing_and_refuses_other_lengths() {
    let mut rng = SplitMix(7);
    let t1 = t1_from(|_, _| rng.coefficient());
    let key = pack([9; RHO_LEN], &t1);
    assert_eq!(decode_t1(&key), Some(t1));
    // A real key round-trips through decode → pack.
    let real = genuine(1);
    let decoded = decode_t1(&real).unwrap();
    let rho: [u8; RHO_LEN] = real[..RHO_LEN].try_into().unwrap();
    assert_eq!(pack(rho, &decoded), real);
    for len in [0, 1, RHO_LEN, PUBLIC_KEY_LEN - 1, PUBLIC_KEY_LEN + 1] {
        assert_eq!(decode_t1(&vec![0x5a; len]), None, "{len}");
        assert_eq!(check(&vec![0x5a; len]), Err(Refusal::Length), "{len}");
    }
    // The reviewer's packing: coefficient 0 of polynomial 0 in bytes 32, 33.
    let mut key = vec![0u8; PUBLIC_KEY_LEN];
    key[32] = 0xff;
    key[33] = 0x02;
    let t1 = decode_t1(&key).unwrap();
    assert_eq!(t1[0][0], 0x2ff);
    assert_eq!(t1.iter().flatten().filter(|&&c| c != 0).count(), 1);
}

#[test]
fn the_challenge_set_is_fixed_and_shaped_like_sample_in_ball() {
    let set = challenges().unwrap();
    assert_eq!(set.len(), CHALLENGES);
    let mut seen = std::collections::BTreeSet::new();
    let mut negatives = 0usize;
    for challenge in set {
        let dense = challenge.dense();
        assert_eq!(dense.iter().filter(|&&c| c != 0).count(), TAU);
        assert!(dense.iter().all(|&c| (-1..=1).contains(&c)));
        negatives += dense.iter().filter(|&&c| c < 0).count();
        assert!(seen.insert(dense.to_vec()), "a repeated challenge");
    }
    // Signs are balanced (7680 signs: mean 3840, sd 44).
    assert!((3500..4180).contains(&negatives), "{negatives}");
    // Reproducible: the first challenge's positions are pinned.
    let first: Vec<usize> = set[0]
        .dense()
        .iter()
        .enumerate()
        .filter(|(_, c)| **c != 0)
        .map(|(i, _)| i)
        .collect();
    let again: Vec<usize> = sample_in_ball(0)
        .unwrap()
        .dense()
        .iter()
        .enumerate()
        .filter(|(_, c)| **c != 0)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(first, again);
}

#[test]
fn the_fast_measurement_agrees_with_the_literal_oracle() {
    let mut rng = SplitMix(11);
    let keys: Vec<T1> = vec![
        decode_t1(&genuine(2)).unwrap(),
        t1_from(|_, _| rng.coefficient()),
        t1_from(|_, _| 512),
        t1_from(|row, i| if (i + row) % 3 == 0 { 512 } else { 1 }),
        t1_from(|_, i| i32::from(i == 17)),
        t1_from(|_, _| 1023),
    ];
    let set = challenges().unwrap();
    for (n, t1) in keys.iter().enumerate() {
        let fast = challenge_counts(t1).unwrap();
        // Every 9th challenge (the oracle is slow in a debug build).
        for (index, challenge) in set.iter().enumerate().step_by(9) {
            let c = challenge.dense();
            for row in 0..K {
                assert_eq!(
                    fast[index][row],
                    oracle_count(&c, &t1[row]),
                    "key {n}, challenge {index}, row {row}"
                );
            }
        }
    }
}

#[test]
fn genuine_keys_pass_with_wide_margins() {
    for seed in 0..24 {
        let key = genuine(seed);
        assert_eq!(check(&key), Ok(()), "seed {seed}");
        let counts = challenge_counts(&decode_t1(&key).unwrap()).unwrap();
        let min_row = counts.iter().flatten().min().unwrap();
        let min_total = counts
            .iter()
            .map(|r| r.iter().sum::<usize>())
            .min()
            .unwrap();
        // 5+ standard deviations above each threshold.
        assert!(
            *min_row >= MIN_ROW_NONZERO + 40,
            "seed {seed}: row {min_row}"
        );
        assert!(
            min_total >= MIN_TOTAL_NONZERO + 150,
            "seed {seed}: total {min_total}"
        );
    }
    // Uniformly random `t1`s (not from a key generation) behave alike.
    let mut rng = SplitMix(5);
    for _ in 0..8 {
        let t1 = t1_from(|_, _| rng.coefficient());
        assert_eq!(prefilter(&t1), Ok(()));
        assert_eq!(statistical(&t1), Ok(()));
    }
}

/// Structured `t1`s: each is refused by the full check, and the forgeable
/// ones by the measurement ALONE (the pre-filters are a fast path, not the
/// defense). The three the measurement passes (coarse multiples of 128,
/// 16 random coefficients per polynomial, a long period) spread
/// `c·t1·2^d` over most of Z_q, so no forgery is known for them; the
/// pre-filters refuse them anyway, because no generated key looks like
/// that.
#[test]
fn structured_keys_are_refused() {
    let mut rng = SplitMix(13);
    let random_row: [i32; N] = std::array::from_fn(|_| rng.coefficient());
    // (name, t1, refused by the measurement alone)
    let cases: Vec<(&str, T1, bool)> = vec![
        ("all zero", t1_from(|_, _| 0), true),
        (
            "one coefficient = 1 (the reviewer's key)",
            t1_from(|row, i| i32::from(row == 0 && i == 0)),
            true,
        ),
        (
            "one coefficient = 1 per polynomial",
            t1_from(|_, i| i32::from(i == 0)),
            true,
        ),
        ("every coefficient 512", t1_from(|_, _| 512), true),
        ("every coefficient 1", t1_from(|_, _| 1), true),
        ("every coefficient 1023", t1_from(|_, _| 1023), true),
        ("every coefficient 511", t1_from(|_, _| 511), true),
        ("every coefficient 513", t1_from(|_, _| 513), true),
        (
            "512 on even positions, 0 on odd",
            t1_from(|_, i| if i % 2 == 0 { 512 } else { 0 }),
            true,
        ),
        (
            "512 or 0 at random",
            t1_from(|_, _| if rng.next() & 1 == 1 { 512 } else { 0 }),
            true,
        ),
        (
            "small values (0..8)",
            t1_from(|_, _| i32::try_from(rng.next() % 8).unwrap()),
            true,
        ),
        (
            "512 plus small noise",
            t1_from(|_, _| 510 + i32::try_from(rng.next() % 5).unwrap()),
            true,
        ),
        (
            "multiples of 256",
            t1_from(|_, _| 256 * i32::try_from(rng.next() % 4).unwrap()),
            true,
        ),
        (
            "multiples of 128",
            t1_from(|_, _| 128 * i32::try_from(rng.next() % 8).unwrap()),
            false,
        ),
        (
            "sparse: 16 random coefficients per polynomial",
            t1_from(|_, i| {
                if i % 16 == 0 {
                    1 + i32::try_from(rng.next() % 1023).unwrap()
                } else {
                    0
                }
            }),
            false,
        ),
        (
            "a random polynomial repeated with period 2",
            t1_from(|_, i| random_row[i % 2]),
            true,
        ),
        (
            "a random polynomial repeated with period 100",
            t1_from(|_, i| random_row[i % 100]),
            false,
        ),
        (
            "a random polynomial repeated with period 64",
            t1_from(|_, i| random_row[i % 64]),
            false,
        ),
        (
            "one constant-512 polynomial, seven random",
            t1_from(|row, i| {
                if row == 3 {
                    512
                } else {
                    random_row[(i * 7 + row) % N]
                }
            }),
            true,
        ),
        (
            "one all-zero polynomial, seven random",
            t1_from(|row, i| {
                if row == 5 {
                    0
                } else {
                    random_row[(i * 11 + row) % N]
                }
            }),
            true,
        ),
        (
            "(X + 1)^255 mod 2, times 512",
            t1_from(|_, i| 512 * i32::from(binomial_parity(255, i))),
            true,
        ),
        (
            "(X + 1)^230 mod 2, times 512",
            t1_from(|_, i| 512 * i32::from(binomial_parity(230, i))),
            true,
        ),
    ];
    for (name, t1, by_measurement) in cases {
        let key = pack([0x5a; RHO_LEN], &t1);
        assert!(check(&key).is_err(), "{name}: accepted");
        if by_measurement {
            assert_eq!(statistical(&t1), Err(Refusal::Forgeable), "{name}");
        }
    }
}

/// `C(n, i) mod 2` (Lucas): the coefficients of `(X + 1)^n` over GF(2).
fn binomial_parity(n: usize, i: usize) -> bool {
    i <= n && (i & n) == i
}

/// The pre-filters name what they catch.
#[test]
fn the_prefilters_catch_their_shapes() {
    let mut rng = SplitMix(17);
    let random_row: [i32; N] =
        std::array::from_fn(|_| 1 + i32::try_from(rng.next() % 1023).unwrap());
    assert_eq!(prefilter(&t1_from(|_, _| 0)), Err(Refusal::ZeroT1));
    assert_eq!(
        prefilter(&t1_from(|_, i| i32::from(i < 127) * random_row[i])),
        Err(Refusal::LowWeight)
    );
    assert_eq!(
        prefilter(&t1_from(|_, i| random_row[i % MAX_PERIOD])),
        Err(Refusal::Periodic)
    );
    assert_eq!(
        prefilter(&t1_from(|_, i| random_row[i % (MAX_PERIOD - 3)])),
        Err(Refusal::Periodic)
    );
    assert_eq!(prefilter(&t1_from(|_, _| 77)), Err(Refusal::LowEntropy));
    assert_eq!(
        prefilter(&t1_from(|_, i| random_row[i % (MIN_DISTINCT - 1)])),
        Err(Refusal::LowEntropy)
    );
    assert_eq!(
        prefilter(&t1_from(|_, i| 1 + 16 * (random_row[i] % 64))),
        Err(Refusal::LowEntropy)
    );
    // Not periodic, half weight: the pre-filters pass it on.
    assert_eq!(
        prefilter(&t1_from(|_, i| i32::from(i < 128) * random_row[i])),
        Ok(())
    );
    assert_eq!(prefilter(&t1_from(|_, i| random_row[i])), Ok(()));
}

/// The false-reject measurement behind the thresholds: many keys from
/// AWS-LC's key generation, every count recorded. Run it with
/// `cargo test --release -p seaworthy-crypto -- --ignored --nocapture
/// intake_false_reject_measurement` (`SEAWORTHY_INTAKE_KEYS` sets the
/// number of keys, default 10000).
#[test]
#[ignore = "a measurement over thousands of keys; run in release"]
fn intake_false_reject_measurement() {
    let keys: u64 = std::env::var("SEAWORTHY_INTAKE_KEYS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(10_000);
    let (mut refused, mut rows, mut totals) = (0u64, Stats::default(), Stats::default());
    for seed in 0..keys {
        let mut bytes = [0u8; SEED_LEN];
        crate::rand::fill(&mut bytes).unwrap();
        let _ = seed;
        let key = SigningKey::from_seed(&bytes).unwrap().public_key();
        if check(&key).is_err() {
            refused += 1;
        }
        for counts in challenge_counts(&decode_t1(&key).unwrap()).unwrap() {
            for &count in &counts {
                rows.add(count);
            }
            totals.add(counts.iter().sum());
        }
    }
    println!("keys: {keys}, refused: {refused}");
    println!(
        "per polynomial: n = {}, mean {:.2}, sd {:.2}, min {} (threshold {MIN_ROW_NONZERO}, {:.1} sd below the mean)",
        rows.n,
        rows.mean(),
        rows.sd(),
        rows.min,
        (rows.mean() - MIN_ROW_NONZERO as f64) / rows.sd()
    );
    println!(
        "total: n = {}, mean {:.2}, sd {:.2}, min {} (threshold {MIN_TOTAL_NONZERO}, {:.1} sd below the mean)",
        totals.n,
        totals.mean(),
        totals.sd(),
        totals.min,
        (totals.mean() - MIN_TOTAL_NONZERO as f64) / totals.sd()
    );
    assert_eq!(refused, 0);
}

#[derive(Default)]
struct Stats {
    n: u64,
    sum: f64,
    sum_sq: f64,
    min: usize,
}

impl Stats {
    fn add(&mut self, value: usize) {
        if self.n == 0 || value < self.min {
            self.min = value;
        }
        self.n += 1;
        let v = value as f64;
        self.sum += v;
        self.sum_sq += v * v;
    }

    fn mean(&self) -> f64 {
        self.sum / self.n as f64
    }

    fn sd(&self) -> f64 {
        (self.sum_sq / self.n as f64 - self.mean() * self.mean()).sqrt()
    }
}
