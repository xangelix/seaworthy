# seaworthy

Build, package, sign, ship and update Rust applications on Linux, Windows and macOS, from one
configuration file, with every piece optional.

> **Status: pre-release.** The crates are being extracted from a production distribution
> pipeline and are not yet published. Interfaces and on-disk formats may change until 1.0.

## What it does

- **CPU-level builds.** Compile the application once per CPU level (for example x86-64-v2/v3/v4,
  Zen 4, Apple M-series) and ship a small launcher that picks the best core the machine can run,
  with a portable fallback.
- **Packages.** Linux `.deb`/`.rpm`/Arch packages and signed repositories, Windows MSI, macOS
  `.pkg`, plain archives. Each format is opt-in.
- **Signing and verification.** Release manifests signed with ML-DSA-87, ECDSA P-256 or Ed25519;
  Authenticode and Apple code signing hooks; verification of every produced artifact before it
  is published.
- **Services.** One service description rendered to systemd units, Windows services and launchd
  jobs, with least-privilege defaults, plus the runtime glue a service binary needs.
- **Updates.** A privileged update helper that installs only signed releases through the
  platform's own package manager, under administrator-controlled policy.
- **CI.** Reusable GitHub Actions workflows (and GitLab CI templates) that run the whole pipeline.

## Crates

| Crate | Purpose |
|---|---|
| `seaworthy-levels` | CPU levels, feature detection, binary requirement records |
| `seaworthy-launcher` | The launcher and the core entry point |
| `seaworthy-crypto` | Signatures, digests, randomness and TLS on AWS-LC (optional FIPS module) |
| `seaworthy-formats` | Release identifiers, the signed release manifest, the product model |
| `seaworthy-service` | Service description, renderers (systemd, Windows, launchd) and runtime |
| `seaworthy-updater` | Update requests, policy, the update helper and installers |
| `seaworthy` | The command-line tool: plan, build, package, sign, verify, publish |

Use only the crates (and features) you need: a local-only desktop tool can take the launcher and
packaging alone; a product with a server can add services and updates.

## Security

See [SECURITY.md](SECURITY.md) to report a vulnerability, and
[docs/threat-model.md](docs/threat-model.md) for what seaworthy defends against.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in
this project by you, as defined in the Apache-2.0 license, shall be dual licensed as above,
without any additional terms or conditions.
