# seaworthy-formats

*The signed contract between release tooling and the update helper, in one small, pure crate.*

Everything the seaworthy CLI (which builds, signs and publishes releases) and
`seaworthy-updater` (whose privileged helper verifies and installs them) must agree on:

| Item | What |
|---|---|
| `ReleaseManifest`, `ManifestTrust`, `ReleaseKey` | The signed release statement, the key set a helper trusts, and key intake |
| `release` | Release versions and sequences, their order, every package format's spelling, the byte-exact read-back |
| `Product` | A product's names, read from `seaworthy.toml` (`Product::from_config`) |
| `ArtifactFormat`, `format_check` | What an artifact is, and the magic a verified package must start with |
| `UpdatePolicy` | The update-policy values (`auto`, `notify`, `off`); reading the machine's policy is the updater's |
| `DigestAlgorithm`, `SignatureAlgorithm` | SHA-256/SHA-512; ML-DSA-87, ECDSA P-256, Ed25519 |
| `validate_version`, `MAX_*` | The version-token gate and the size limits |

**Pure.** No I/O, no async runtime, no network, process or OS dependency, `#![forbid(unsafe_code)]`,
and no index or arithmetic that can panic. Cryptography goes through `seaworthy-crypto`; the
network-facing parsers are fuzzed (`fuzz/`, target `updater_manifest`).

## The rules

1. **A statement, not a digest, is signed.** A signature over a bare digest says *these bytes*,
   not *which release*: storage or a CDN could serve another target's build, an older version or
   another product's package. The manifest binds product, channel, version and build, sequence,
   target, format, size and digest, and a helper verifies it before it fetches any package byte.
2. **One spelling.** The statement is canonical (length-prefixed text fields, fixed order, the
   verifier re-encodes and requires byte equality), and so is the signature block.
3. **Keys are validated at intake.** `ReleaseKey::new` refuses forgeable keys (ML-DSA-87 keys
   `seaworthy-crypto`'s intake test refuses, such as an all-zero, low-weight or structured
   `t1`; small-order Ed25519 points), off-curve P-256 points, compressed P-256 spellings, and
   algorithms `seaworthy-crypto`'s gate doesn't admit. FIPS 204 defines no public-key
   validation, so the ML-DSA test is defense in depth: embed only keys from your own
   `seaworthy keygen` or HSM, or received from their holder over an authenticated channel.
   Install `seaworthy-crypto`'s algorithm policy, if you install one, before the first key is
   built.
4. **Verify first, compare second.** `ManifestTrust::verify` checks the signature before it
   looks at any field, so mismatch errors only ever describe authenticated content.

## Example

Sign a release statement, then check it exactly as the update helper does:

```rust
use seaworthy_formats::{
    ArtifactFormat, DigestAlgorithm, ManifestSignature, ManifestTrust, ReleaseKey,
    ReleaseManifest, SignatureAlgorithm, TARGET_TRIPLE, release_key_id,
};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
// Release side: a key (its seed is the root secret; keep it in a KMS or
// HSM), the statement, one signature line per key.
let mut seed = [0u8; seaworthy_crypto::mldsa::SEED_LEN];
seaworthy_crypto::rand::fill(&mut seed)?;
let key = seaworthy_crypto::mldsa::SigningKey::from_seed(&seed)?;
let package = b"the package bytes";
let manifest = ReleaseManifest {
    product: "acme-agent".into(),
    channel: Some("stable".into()),
    version: "1.4.0".into(),
    build: "a1b2c3".into(),
    sequence: 812,
    target: TARGET_TRIPLE.into(),
    format: ArtifactFormat::Deb,
    size: package.len() as u64,
    digest_algorithm: DigestAlgorithm::Sha512,
    digest: DigestAlgorithm::Sha512.hash(package),
};
let statement = manifest.statement()?;
let signed = manifest.encode_signed(&[ManifestSignature {
    algorithm: SignatureAlgorithm::MlDsa87,
    key_id: release_key_id(SignatureAlgorithm::MlDsa87, &key.public_key()),
    signature: key.sign(&statement).to_vec(),
}])?;

// Helper side: the public key compiled in, the token the product's server
// names, the format the machine's installer takes.
let trust = ManifestTrust::new(
    "acme-agent",
    [ReleaseKey::new(key.public_key().to_vec(), SignatureAlgorithm::MlDsa87)?],
)?
.channel("stable")?;
let verified = trust.verify(&signed, "1.4.0+a1b2c3", ArtifactFormat::Deb)?;
assert_eq!(verified, manifest);
// Another build of the same version is refused, signature or not.
assert!(trust.verify(&signed, "1.4.0+ffffff", ArtifactFormat::Deb).is_err());
# Ok(()) }
```

## The signed manifest

`{package url}.manifest`:

```text
seaworthy-release-manifest:1
product=10:acme-agent
channel=6:stable
version=5:1.4.0
build=6:a1b2c3
sequence=812
target=24:x86_64-unknown-linux-gnu
format=deb
size=48213504
digest=sha512:<128 lowercase hex>

signature=ml-dsa-87:<16 hex key id>:<hex signature>
signature=ed25519:<16 hex key id>:<hex signature>
```

- The **statement** (up to the blank line) is what every signature covers; its first line is the
  domain separator. Text fields are `name=<byte length>:<value>`; the channel line is always
  present (`channel=0:` for none); `build` is the version token's build metadata (`build=0:` for
  none), and `version` carries no `+`. The helper compares the server's token with
  `version+build` byte for byte.
- `sequence` (at least 1) orders two builds of one version; `format` is one of `msi`, `zip`,
  `deb`, `rpm`, `pacman`, `tar`, `pkg`; `size` is exact and non-zero.
- The **signature block**: 1 to 8 lines, lowercase hex, a final newline, no key signing twice.
  Lines naming a key the helper doesn't trust are skipped; any trusted key verifying is enough
  (key rotation).

## Release keys

| Algorithm | Wire tag | Public key bytes |
|---|---|---|
| ML-DSA-87 | `ml-dsa-87` | raw, 2592 bytes |
| ECDSA P-256/SHA-256 | `ecdsa-p256` | SPKI DER of an uncompressed point, or the raw 65-byte point (stored as SPKI) |
| Ed25519 | `ed25519` | raw, 32 bytes |

**Key id** = the first 8 bytes of SHA-256(`seaworthy-release-key:1:{tag}:` ‖ public key): a
selector, never an authenticator.

**Rotation:** ship a helper build trusting the old and the new key, sign releases with both, and
drop the old key once the fleet runs the two-key build. A suspected leak follows the same path,
as fast as the fleet updates.

## `seaworthy.toml`

`Product::from_config(text, id)` reads only the keys that name things (anything else is
ignored; the seaworthy CLI validates the whole file):

```toml
[defaults]
vendor = "Acme"                  # required
channel = "stable"               # required

[product.agent]
display-name = "Acme Agent"      # required
executable = "AcmeAgent"         # required
windows-directory = "Agent"      # optional: else the display name's last word
updates.default = "auto"         # optional: auto | notify | off (default auto)

[product.agent.service]          # optional: a service product
name = "AcmeAgent"               # required in the table
state-directory = "acme/agent"   # optional: holds the Linux update request file

[product.agent.macos]            # optional: macOS outputs
bundle-id = "com.example.agent"  # required in the table
```

## Features

None. The FIPS posture rides `seaworthy-crypto/fips`, which applications set.

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
