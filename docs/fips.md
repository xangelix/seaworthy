# FIPS builds

What the `fips` feature of `seaworthy-crypto` does, what a FIPS build needs, and how to check
a FIPS release binary.

## What `fips` does

`seaworthy-crypto/fips` links the **AWS-LC FIPS 4.2.0** module (CMVP: in process, Comment
Resolution; its validated predecessor is AWS-LC 3, certificate #5314), built from source by
`aws-lc-fips-sys` 0.14.2 behind `aws-lc-rs` 1.18.1. Both are pinned with `=` in the workspace
manifest, and the linked module is asserted at runtime (`seaworthy_crypto::module`). Say
"validated" only once a certificate names 4.2.0.

The feature also enables `rustls/fips`. Feature unification carries it to every rustls AWS-LC
provider in the graph, so TLS offers only FIPS-approved cipher suites and key-exchange groups
(no ChaCha20-Poly1305, no plain X25519; the hybrid `X25519MLKEM768` and `SECP256R1MLKEM768`
groups stay, on rustls's SP 800-56Cr2 reading that the approved component decides; have your
assessor confirm that reading).

Applications enable the feature; libraries never set it. `seaworthy_crypto::is_fips()` answers
`true` only when the backend is the FIPS module in FIPS mode and the TLS provider (and any
installed rustls process default) reports FIPS. It attests module linkage and TLS filtering,
not that only approved services ran: the X25519 half of the hybrid key exchange is not approved
by the module's service indicator.

### Signature schemes

| Scheme | Approved by the linked 4.2.0 module | On the validated AWS-LC 3 certificate |
|---|---|---|
| ML-DSA-87 | yes | no |
| ECDSA P-256/SHA-256 | yes | yes |
| Ed25519 | yes | yes |

A deployment that must use only what a validated certificate lists today installs
`fips_policy::AlgorithmPolicy::CERTIFIED_ONLY` at boot; intake points then refuse ML-DSA-87.

## What a FIPS build needs

The module is compiled from C sources during the build, so a FIPS build needs, besides Rust:

- a **C compiler**: clang (the module's CMake build is validated with clang); MSVC on Windows;
- **CMake**, **Go** and **Perl** (the module build runs Go and Perl code generators);
- on Windows, the MSVC toolchain only (the FIPS module does not support other Windows
  toolchains).

The module build is sensitive to the C toolchain. For release builds, pin the C compiler, CMake,
Go and Perl versions in your build image, not just Rust, and bump them deliberately. Build Linux
releases on a distribution old enough for the glibc your users run: the AWS-LC C code picks up
newer glibc symbols on a newer build host.

### Environment the build requires and refuses

The repository's `.cargo/config.toml` sets the two switches a FIPS build needs. An application
building `fips` outside this repository sets them too:

```toml
[env]
AWS_LC_FIPS_SYS_CC = "clang"
AWS_LC_FIPS_SYS_USE_SYSTEM = "0"
```

`AWS_LC_FIPS_SYS_USE_SYSTEM=0` is **required**: without it `aws-lc-fips-sys` auto-detects a
pre-installed AWS-LC (`OPENSSL_DIR`, `OPENSSL_LIB_DIR`, pkg-config) and links that instead of
building the pinned module.

The AWS-LC Security Policy's build procedure admits "no additions, deletions, or alterations".
Under `fips`, `seaworthy-crypto`'s build script therefore refuses, with a build error naming the
variable, every knob that silently changes what goes into the module:

- `AWS_LC_FIPS_SYS_*` variables other than the tool selection (`CC`, `CXX`, `HOST_*`,
  `TARGET_*`, `CMAKE`, `CMAKE_GENERATOR`), for example `SMALL`, `NO_ASM`, `SANITIZER`, `C_STD`,
  `CFLAGS`, `SYSTEM_DIR`; unknown ones too;
- C flags that reach the module build: `CFLAGS`, `CXXFLAGS`, `HOST_CFLAGS`, `TARGET_CFLAGS`,
  `CFLAGS_<target>`, `ASMFLAGS`, `CRATE_CC_NO_DEFAULTS`, `CMAKE_TOOLCHAIN_FILE`;
- Rust codegen flags that cc-rs passes into every C build it drives: `-C target-feature` (except
  `crt-static`), `code-model`, `relocation-model`, PGO, `force-frame-pointers`, `lto`,
  `stack-protector` and similar, and `-Z branch-protection`.

`-C target-cpu` is recorded with a warning, not refused: cc-rs does not pass it to C builds.
Builds per CPU level differ by `-C target-feature`, which does reach the module, so build the
FIPS binary once for the baseline CPU, or acknowledge the flag and treat each level as its own
module build.

To allow a knob deliberately, name it in `SEAWORTHY_FIPS_MODULE_BUILD_ACK` (comma-separated
variable names, or `rustflags:<flag>`). It is then stamped into the binary's build provenance,
never silent; a stale acknowledgement warns.

### Build provenance

The build script stamps the toolchain into the binary
(`seaworthy_crypto::module::build_provenance()`): `rustc`, target, profile, optimization level,
whether `fips` was on, and under `fips` the C compiler, CMake, Go and Perl versions, the
module-relevant environment, `-C target-cpu` and any acknowledged knobs. Log it at boot if you
want it in your evidence. `cargo clean -p seaworthy-crypto -p aws-lc-fips-sys` rebuilds the
module and the stamp together.

## Checking a FIPS release binary

From the repository root:

```sh
CARGO_PROFILE_RELEASE_STRIP=false cargo build --release -p seaworthy-crypto \
    --features fips --example fips_selfcheck
scripts/check-fips-binary.sh target/release/examples/fips_selfcheck
target/release/examples/fips_selfcheck --expect-fips
```

- `scripts/check-fips-binary.sh BINARY` is a standalone `nm` check (bash, nm, grep, awk), so you
  can run it over your own release binary. It needs the symbol table: build unstripped, check,
  then strip the shipped copy. It requires the `aws_lc_fips_0_14_2_*` symbols with
  `awslc_version_string` defined in text (the Security Policy's static-link check), and zero
  non-FIPS `aws_lc_<version>_*`, `ring_core_*` or other-version FIPS symbols. `--self-test`
  runs the script's own tests.
- `fips_selfcheck --expect-fips` runs the boot self-check (a module-DRBG draw and the
  pinned-module assertion), `is_fips()`, and prints the module, its CMVP status and the build
  provenance; it fails unless the process runs FIPS.
- `cargo test -p seaworthy-crypto --features fips` runs the FIPS-only tests, including the
  assertion that the linked module is AWS-LC FIPS 4.2.0.

Call `seaworthy_crypto::module::startup_self_check()` first thing in `main` of a FIPS
application: the module's CPU-jitter entropy source runs its startup health tests on the first
random draw and aborts the process when they fail, which is rare on bare metal and more frequent
in small virtual machines. The self-check makes that happen at boot, never mid-request.

## The dependency graph

`scripts/check-crypto-graph.sh` checks the feature-resolved graph of the workspace (default
features, every non-FIPS feature, and `fips`): no `ring`, `openssl`, `openssl-sys`,
`native-tls`, `boring-sys` or `blake3` anywhere; no member depends directly on those or on
`aws-lc-sys`; `aws-lc-rs` and `aws-lc-fips-sys` are reached only through `seaworthy-crypto`; and
`aws-lc-sys` has `aws-lc-rs` as its only parent.

`aws-lc-sys`, the non-FIPS AWS-LC, is still **compiled** in FIPS builds: rustls's `aws_lc_rs`
feature, which `rustls/fips` implies, enables it unconditionally. It is never **linked**:
`aws-lc-rs` binds `aws-lc-fips-sys` under `fips` and nothing else references `aws-lc-sys`. The
graph check keeps it that way and the binary check proves it per release.

## Compliance notes

- `aws-lc-fips-sys` drives the module's CMake build over a pruned source set with a symbol
  prefix; it does not run the Security Policy's build procedure verbatim. If your compliance
  program needs it, get a written statement from AWS or your lab that this build is covered.
- The module's tested operating environments are Amazon Linux 2023 on specific hardware.
  Building and deploying elsewhere is a vendor-affirmed operating environment; record that
  decision in your security documentation.
- Whether the 4.x Security Policy claims an entropy-source certificate for the CPU-jitter
  source (and so whether the SP 800-90B key-strength caveat applies) is to be confirmed from the
  4.x Security Policy when its certificate issues.
