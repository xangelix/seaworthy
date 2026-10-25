# Contributing

## Ground rules

- **Stable Rust only.** The toolchain is pinned in `rust-toolchain.toml`; the minimum supported
  Rust version is `workspace.package.rust-version` in `Cargo.toml`. Raising either is a
  deliberate, separate change.
- **Everything optional.** A caller takes only the crates and features it needs. New platform
  or format support goes behind a feature or a configuration switch, off unless asked for.
- **No organization defaults.** No registry, bucket, secret-store path, signing account, runner
  image or vendor name is a default anywhere, including CI templates and examples. Examples use
  `example.com` and the product name `Acme`.
- **Formats are a contract.** Every on-disk or signed format carries a `seaworthy-<name>:<n>`
  tag. Changing a format's meaning means a new tag version and a migration note in the changelog.

## Code

- Library code never panics on input: `unwrap`, `expect`, `panic!`, `todo!` and friends are
  denied by the workspace lints (tests may use them).
- Parsers of untrusted input deny `clippy::indexing_slicing` and
  `clippy::arithmetic_side_effects` in their crate root, and have a fuzz target under `fuzz/`.
- `unsafe` is denied workspace-wide. FFI modules allow it per block, each with a `// SAFETY:`
  comment stating the invariant. Crates without FFI use `#![forbid(unsafe_code)]`.
- Cryptography goes through `seaworthy-crypto` only. No other crate depends on a cryptography or
  TLS backend directly.
- Public items are documented. Errors are typed (`thiserror`), never strings.
- New dependencies are added to `[workspace.dependencies]` and must pass `cargo deny check`.

## Checks

Before sending a change:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
cargo deny check
cargo test --manifest-path fuzz/Cargo.toml   # replay the fuzz corpus
for check in scripts/check-*.sh; do "$check"; done
```

`--all-features` includes `fips`, which builds the AWS-LC FIPS module from source and needs
Clang, CMake, Go and Perl. CI runs clippy and the tests with every other feature on Linux,
Windows and macOS, and with all features (FIPS included) on Linux. It also checks the MSRV,
cargo-deny, the fuzz corpus replay, the check scripts, and the workflows themselves; the fuzz
targets run weekly ([fuzz/README.md](fuzz/README.md)). The toolchain, MSRV and release
procedures are in [docs/releasing.md](docs/releasing.md).

## Commits

One logical change per commit, with a message that says what changed and why. By contributing
you agree that your contribution is licensed under the project's dual MIT / Apache-2.0 license.

## Conduct

Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md).
