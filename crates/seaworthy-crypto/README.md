# seaworthy-crypto

*Every cryptographic operation of the seaworthy crates through one small facade; FIPS is one
feature.*

The seaworthy crate family's **minimal cryptography facade** on
[AWS-LC](https://github.com/aws/aws-lc) via `aws-lc-rs`. It covers exactly what the
distribution stack needs, and nothing else:

| Module | What |
|---|---|
| `digest` | SHA-256 and SHA-512, one-shot (`sha256`, `sha512`, `_hex` forms) and streaming (`Sha256`, `Sha512`); `sha1_for_identifiers` for identifiers whose definition fixes SHA-1 |
| `mldsa` | ML-DSA-87 (FIPS 204): seed-deterministic `SigningKey`, `verify`, `validate_public_key` |
| `ecdsa` | ECDSA P-256/SHA-256 (DER signatures, SPKI public keys) |
| `ed25519` | Ed25519, with small-order and non-canonical key rejection |
| `rand` | `fill` from the AWS-LC DRBG |
| `tls` | the TLS policy (hybrid post-quantum key exchange first) and `client_config_builder()` |
| `fips_policy` | the algorithm-admission gate (`ensure_approved`) and the deployment's policy |
| `module` | the linked module's identity, the boot self-check, the build provenance |

plus `ct_eq` (constant-time compare), `is_fips()`, `tls_provider()` and
`install_default_tls_provider()` at the crate root.

**No primitives are implemented here.** Everything delegates to AWS-LC. With the `fips`
feature that is the AWS-LC FIPS 4.2.0 module (CMVP: in process, Comment Resolution; its
validated predecessor is AWS-LC 3, certificate #5314), pinned with `=` and asserted at runtime.

## The rules

1. **Cryptography enters the workspace through this facade and nowhere else.** No other
   seaworthy crate depends on `aws-lc-rs`, `rustls` providers or another backend directly
   (`scripts/check-crypto-graph.sh` enforces it). One review target, and feature unification
   is what makes the `fips` feature flip the whole tree, rustls included.
2. **FIPS is one switch, and it never degrades silently.** The `fips` feature lives here only
   (applications set it, libraries never). The build script refuses a `fips` build whose
   environment would link a pre-installed AWS-LC or alter the module build; `is_fips()`
   answers `true` only when the backend AND the TLS provider report FIPS; the module version
   is asserted at runtime (`module::ensure_expected_module`).
3. **Keys are validated at intake.** `mldsa::validate_public_key` refuses the all-zero `t1`
   key and `ed25519::validate_public_key` the small-order and non-canonical points, both of
   which would otherwise let anyone forge a signature without a secret; both checks also run
   inside `verify`. ECDSA points are validated by AWS-LC itself.
4. **The crate takes key bytes; custody is the caller's.** PKCS#8 documents come back in
   `Zeroizing` buffers; where seeds and documents live (a KMS, an HSM, a sealed secret store)
   is the deployment's decision.

## Example

Release signing and verification with ML-DSA-87, a streamed artifact digest, and a TLS client
configuration on the canonical provider:

```rust
# fn main() -> Result<(), Box<dyn std::error::Error>> {
use seaworthy_crypto::{digest, fips_policy, mldsa, rand};

// The boot self-check: the first DRBG draw (and, under `fips`, the
// pinned-module assertion) happens here, before any work.
seaworthy_crypto::module::startup_self_check()?;

// A release key: the 32-byte seed is the root secret.
let mut seed = zeroize::Zeroizing::new([0u8; mldsa::SEED_LEN]);
rand::fill(&mut *seed)?;
let key = mldsa::SigningKey::from_seed(&*seed)?;
let public_key = key.public_key();

// The artifact digest, streamed in chunks.
let mut hasher = digest::Sha512::new();
for chunk in [b"release ".as_slice(), b"artifact"] {
    hasher.update(chunk);
}
let artifact_digest = hasher.finish();
assert_eq!(artifact_digest, digest::sha512(b"release artifact"));

// Sign at release time; verify on the client, after the intake gate.
let signature = key.sign(&artifact_digest);
fips_policy::ensure_approved(fips_policy::Service::MlDsa87)?;
mldsa::validate_public_key(&public_key)?;
mldsa::verify(&public_key, &artifact_digest, &signature)?;

// Digests are compared in constant time.
let expected = digest::sha512_hex(b"release artifact");
assert!(seaworthy_crypto::ct_eq(expected.as_bytes(), hex::encode(artifact_digest).as_bytes()));

// A TLS client configuration on the policy's provider and versions (add
// your verifier, e.g. the platform verifier, then client auth).
let _builder = seaworthy_crypto::tls::client_config_builder()?;
# Ok(()) }
```

## Features

| Feature | Effect |
|---|---|
| `fips` | Links the AWS-LC FIPS 4.2.0 module (built from source: needs a C toolchain, CMake, Go and Perl; see [docs/fips.md](https://github.com/xangelix/seaworthy/blob/main/docs/fips.md)) and enables `rustls/fips`, so only FIPS-approved TLS suites and groups exist |

## TLS policy

The canonical provider offers `X25519MLKEM768`, then `SECP256R1MLKEM768`, then the classical
groups (no plain X25519 under `fips`). A deployment can change the policy at boot, before the
first TLS use, through `tls::TlsPolicy::from_config` and `tls::install_policy`, reading the
keys `SEAWORTHY_TLS_GROUPS`, `SEAWORTHY_TLS_MIN_VERSION`, `SEAWORTHY_TLS_REQUIRE_HYBRID` and
`SEAWORTHY_TLS_SUITES`.

## FIPS status of the signature schemes

| Scheme | Approved by the linked 4.2.0 module | On the validated AWS-LC 3 certificate |
|---|---|---|
| ML-DSA-87 | yes | no |
| ECDSA P-256/SHA-256 | yes | yes |
| Ed25519 | yes | yes |

`fips_policy::AlgorithmPolicy::CERTIFIED_ONLY` admits only what a validated certificate lists
today (it refuses ML-DSA-87); `AlgorithmPolicy::ML_DSA_87_ONLY` admits only the post-quantum
scheme.

## Caveats

- **ECDSA signatures are malleable.** `(r, n−s)` verifies wherever `(r, s)` does; never use
  signature bytes as a uniqueness key. Anchor on the message digest.
- **`is_fips()` attests module linkage and TLS filtering**, not that only approved services
  ran (the X25519 half of the hybrid key exchange is not approved by the module's indicator).
- **SHA-1** exists only as `digest::sha1_for_identifiers`, for identifiers such as the
  Windows virtual-account SID; the workspace `clippy.toml` disallows it outside reasoned call
  sites.

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
