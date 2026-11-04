# FIPS builds

What the `fips` feature of `seaworthy-crypto` does, what a FIPS build needs, and how to check
a FIPS release binary.

## What `fips` does

`seaworthy-crypto/fips` links the **AWS-LC FIPS 4.2.0** module (CMVP: in process, Comment
Resolution; its validated predecessor is AWS-LC 3, certificate #5314), built from source by
`aws-lc-fips-sys` behind `aws-lc-rs`. Say "validated" only once a certificate names 4.2.0.

### The module allowlist

`seaworthy-crypto` declares a **range** of both crates (`aws-lc-fips-sys >=0.14.2, <0.15`,
`aws-lc-rs >=1.18.2, <2`), not exact pins: an exact pin in a library forces every library in a
graph (seaworthy-crypto, carpc_crypto, an application's own) to move in lockstep. The
application's `Cargo.lock` picks the releases, and the **FIPS allowlist**,
`crates/seaworthy-crypto/fips-allowlist.txt`, decides which of them a FIPS build may link:

| `aws-lc-fips-sys` | AWS-LC FIPS module | Branch | Status |
|---|---|---|---|
| `0.14.2` | 4.2.0 | 4 | CMVP: in process, Comment Resolution |
| `0.14.3` | 4.2.0 | 4 | CMVP: in process, Comment Resolution |
| `0.14.4` | 4.2.0 | 4 | CMVP: in process, Comment Resolution |

and `aws-lc-rs` 1.18.2 and 1.19.0, both of which bind the 0.14 series. 0.14.4 builds AWS-LC
commit `b67630c7…`, the head of AWS's `fips-2025-09-12-lts` branch on 2026-10-23: the `v4.2.0`
tag plus seven backports to libssl, X.509, the error tables and the build. `crypto/fipsmodule`
and `third_party/jitterentropy` are byte for byte those of 0.14.2 and 0.14.3, and the three
releases read the same build-environment knobs.

The file is the one source of truth in this repository. A module that is not on it is refused at
every point:

- **build time:** `seaworthy-crypto`'s build script reads the releases the graph resolved (Cargo's
  `DEP_*` metadata; both crates name their release in their `links` key) and fails a `fips` build
  whose `aws-lc-fips-sys` is not listed, or whose `aws-lc-rs` binds another release (a future
  `aws-lc-rs` that moves to another sys series would bring a second module into the graph). The
  same script turns the file into `seaworthy_crypto::module::FIPS_MODULES`;
- **startup:** `seaworthy_crypto::module::startup_self_check()` holds the module the process
  links, read at runtime (its version, FIPS mode, its branch), to the allowlist entry of the
  release the build linked, and reports both (`LinkedModule::identity`: `AWS-LC FIPS 4.2.0
  (aws-lc-fips-sys 0.14.4, aws-lc-rs 1.19.0)`; the build provenance records them too);
- **CI:** `scripts/check-fips-lock.sh` holds every lockfile to the list (one release of each
  crate, both listed); the `fips` tests run the startup check;
- **release binaries:** `scripts/verify-fips-binary.sh` requires exactly one module's symbols, of
  a listed release, and `seaworthy verify` the module the product declares.

**Applications pin exactly, in their own lockfile.** Commit `Cargo.lock`, name the module in
`seaworthy.toml` (`[defaults] fips-module`, below), and have CI check that the locked
`aws-lc-fips-sys` and `aws-lc-rs` are on the allowlist and that `aws-lc-fips-sys` is the declared
module (carpc's `scripts/check-fips-lock.sh` does this for a carpc application). A `cargo
update` that moves the module then fails CI until the declaration moves with it, a reviewed edit.

The same file, byte for byte, is kept in carpc (`crates/carpc_crypto/fips-allowlist.txt`) and
tg_spade (`crates/spade-aws-lc-fips/fips-allowlist.txt`); this repository's is the reference.
Their lockfile checks compare their copy with the one in the seaworthy commit they build with, so
a list that drifts fails their CI. A release joins (here first) once it has been built and
checked: a FIPS build with it reports the module version and branch in FIPS mode,
`scripts/verify-fips-binary.sh` accepts its symbols, the knobs it reads are reviewed
(`build/knobs.rs`), and the module's status is in the table above.

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

FIPS 204 defines no ML-DSA public-key validation, and the module performs none: any 2592 bytes
are a key it verifies under, including keys under which a signature computed from public data
verifies. `mldsa::validate_public_key` (run at intake and inside every `mldsa::verify`) adds
seaworthy's intake test, plain arithmetic over the public key outside the module (its fixed
challenges are drawn with the module's SHA-512). It is not part of any validated service and
changes nothing about the module's approval; it refuses the known forgery classes and keys
whose forgeability is measurable, as defense in depth. Trust only keys from your own
`seaworthy keygen` or HSM, or from their holder over an authenticated channel.

### HMAC

HMAC-SHA-256 (the S3 publisher's AWS Signature Version 4) is approved with keys of at least 112
bits (SP 800-131A; the AWS-LC Security Policies' HMAC key length is 112–524288 bits). A shorter
key is `fips_policy::Service::HmacShortKey`: `seaworthy_crypto::hmac` refuses it under `fips`
and under `AlgorithmPolicy::CERTIFIED_ONLY`, and the publisher refuses such a secret when its
S3 client is constructed, before any request.

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
building the allowlisted module.

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
scripts/verify-fips-binary.sh target/release/examples/fips_selfcheck
target/release/examples/fips_selfcheck --expect-fips
```

- `scripts/verify-fips-binary.sh BINARY` is a standalone `nm` check (bash, nm, grep, awk), so you
  can run it over your own release binary. It needs the symbol table: build unstripped, check,
  then strip the shipped copy. `seaworthy layout` strips that way and checks that stripping
  changed nothing the loader maps, the module's code and data included; the Windows version stamp
  and signing are checked the same way
  ([packaging.md](packaging.md#what-changes-after-the-build)). It finds the one module the binary
  links and requires its release to be on the allowlist (`--allowlist FILE`, by default this
  repository's), or to be the release `--module 0.14.4` (or `--prefix aws_lc_fips_0_14_4_`)
  names; it reports the release it found. It requires that release's symbols with
  `awslc_version_string` defined in text (the Security Policy's static-link check), and zero
  non-FIPS `aws_lc_<version>_*`, `ring_core_*` or other-release FIPS symbols. `--self-test`
  runs the script's own tests.
- `fips_selfcheck --expect-fips` runs the boot self-check (a module-DRBG draw and the
  allowlisted-module assertion), `is_fips()`, and prints the module, the crates that built it,
  the allowlist, its CMVP status and the build provenance; it fails unless the process runs FIPS.
- `cargo test -p seaworthy-crypto --features fips` runs the FIPS-only tests, including the
  assertion that the linked module is an allowlisted AWS-LC FIPS 4.2.0 build.

### macOS cores

Off Linux AWS-LC builds the module as a shared library, so a macOS core has none of it and
`scripts/verify-fips-binary.sh`'s static-link check doesn't apply to it (the script does apply to
the module's dylib, and `seaworthy verify` runs its checks there). `seaworthy verify` holds every
core of a FIPS product to its symbol table instead (`seaworthy::verify::fips_macos_core_findings`),
one leading `_` off each Mach-O name:

- it imports the declared module's `aws_lc_fips_<release>_*` symbols and defines none, locally or
  not: a definition is a copy
  of the module that no sidecar ships;
- it has no non-FIPS `aws_lc_<version>_*` symbols, `ring_core_*` symbols or other-version FIPS
  symbols, defined or imported, and no AWS-LC built without a prefix (`awslc_*`, `AWSLC_*`,
  `CRYPTO_library_init`);
- it has local symbols. A stripped Mach-O keeps its imports and exports, which the loader needs, but
  the linker makes everything a static library brought into a Rust `cdylib` local, so stripping
  removes exactly what this check looks for. A stripped core is a finding, never a pass, as on
  Linux.

Build the cores with `strip = false`, as the build plan does (`seaworthy build-plan`,
`CARGO_PROFILE_RELEASE_STRIP=false` by hand). `seaworthy layout` strips no Mach-O.

## A product's module release

A product's cores are built with the `aws-lc-fips-sys` release its own `Cargo.lock` pins, one on
the allowlist. `seaworthy.toml`'s `[defaults] fips-module` names it, and `verify` (and `seaworthy
fips-check --module`) then require that release's symbol prefix
(`aws_lc_fips_<major>_<minor>_<patch>_`) and module libraries (`aws_lc_fips_<…>_crypto.dll`,
`libaws_lc_fips_<…>_crypto.dylib`). `fips-module` accepts exactly the allowlist
(`seaworthy::config::FIPS_MODULES` is `seaworthy_crypto::module::FIPS_MODULES`); unset, it is the
newest release on it (`0.14.4`). Name it: the product's lockfile check compares its locked
`aws-lc-fips-sys` with it, and a default that moves with seaworthy would move the product's
module with it.

Another release joins the allowlist once the module release it builds and its symbol prefix are
confirmed: build a core with it, check it with `scripts/verify-fips-binary.sh --module <release>`,
add it to `fips-allowlist.txt` (and carpc's and tg_spade's copies), and its status to the table
above. Nothing else changes: the checks derive every name from the release.

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
graph check keeps it that way and the binary check proves it per release: over the symbol table of
a Linux core, or of a macOS core ([macOS cores](#macos-cores)).

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
