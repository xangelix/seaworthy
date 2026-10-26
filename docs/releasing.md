# Releasing seaworthy

How seaworthy itself is versioned, built, verified and published, the MSRV policy, and how the
pinned toolchains and CI tools are bumped.

## Versions

- All crates are versioned in lockstep: one `workspace.package.version` in `Cargo.toml`, and the
  `seaworthy-*` entries of `[workspace.dependencies]` carry the same version.
- Semantic Versioning. Before 1.0, a minor release (`0.x` → `0.(x+1)`) may break the API; a
  patch release never does.
- On-disk and signed formats carry their own `seaworthy-<name>:<n>` tags. Changing what a format
  means needs a new tag version and a migration note in the release notes, whatever the crate
  version does.

## Release checklist

1. **Prepare** on a branch:
   - set `workspace.package.version` and the `seaworthy-*` versions in
     `[workspace.dependencies]`;
   - refresh the lockfile for the workspace crates only: `cargo update --workspace`;
   - write the release notes (changes, format changes, MSRV changes, security fixes);
   - run every check in [CONTRIBUTING.md](../CONTRIBUTING.md), then open a pull request and
     merge it to `main` with all required checks green.
2. **Tag** the merge commit on `main` with a signed, annotated tag, and push it:

   ```sh
   git tag --sign v0.2.0 --message "seaworthy 0.2.0"
   git push origin v0.2.0
   ```

3. **Build.** The tag starts `.github/workflows/release.yml`. It checks that the tag names the
   workspace version and points at a commit on `main`, then builds the `seaworthy` CLI for every
   platform below from a clean checkout (no caches), and packages deterministic archives plus
   `SHA256SUMS`.
4. **Approve.** The attestation job runs in the `release` environment: a maintainer approves the
   deployment once the builds are green. It attests the build provenance of every archive and of
   `SHA256SUMS` (Sigstore-signed GitHub attestations), and the next job creates a **draft**
   GitHub release with the files.
5. **Verify the draft** before publishing it. Download the assets, then:

   ```sh
   sha256sum --check SHA256SUMS
   for f in seaworthy-0.2.0-*; do
     gh attestation verify "$f" \
       --repo xangelix/seaworthy \
       --signer-workflow xangelix/seaworthy/.github/workflows/release.yml \
       --source-ref refs/tags/v0.2.0 \
       --deny-self-hosted-runners
   done
   ```

   Run one of the binaries (`seaworthy --version`) on its platform.
6. **Publish** the draft with the release notes.
7. **Publish the crates** to crates.io (below).

A manual run of the release workflow (`workflow_dispatch`) is a dry run: it builds and packages
every platform without attesting or releasing anything. Use it after changing the release
workflow or a build dependency. While `crates/seaworthy` does not exist, the workflow stops
after its plan job.

To rebuild a release, delete the draft (and, if it has to move, the tag) and push the tag again.
The workflow never overwrites an existing release.

## Release binaries

| Target | Runner | Notes |
|---|---|---|
| `x86_64-unknown-linux-musl` | `ubuntu-24.04` | Static binary |
| `aarch64-unknown-linux-musl` | `ubuntu-24.04-arm` | Static binary, native build |
| `x86_64-pc-windows-msvc` | `windows-2025` | Static C runtime (`+crt-static`): no Visual C++ redistributable needed |
| `aarch64-apple-darwin` | `macos-15` | |
| `x86_64-apple-darwin` | `macos-15` | Cross-compiled on Apple silicon |

**Why musl on Linux.** The CLI runs in CI images and on developer machines of every age and
distribution. A glibc build links against the build host's glibc (2.39 on Ubuntu 24.04) and will
not start on older systems such as RHEL 9 or Debian 12 unless it is built in an old-distribution
container, which adds a base image to trust and pin. A static musl binary has no runtime
dependency at all and also runs on musl distributions such as Alpine. The C code in the
dependency graph (AWS-LC) is compiled with Ubuntu's `musl-gcc` (`musl-tools`). musl's memory
allocator is slower than glibc's; if that ever shows in packaging throughput, the CLI can switch
its global allocator without changing the target. The release binaries are built without the
`fips` feature: a FIPS build is built from source by whoever needs it.

**No build paths.** The build remaps the cargo home and the checkout to `/cargo` and `/seaworthy`
(`--remap-path-prefix`; AWS-LC's build maps its C sources itself), so the binaries don't carry the
runner's directories, and a build step fails if one still names the checkout, the cargo home or
the home directory. The same commit, toolchain and lockfile then build the same bytes wherever the
directories are; the archives around them are deterministic (`scripts/ci/package-release.sh`).

## Publishing to crates.io

Publishing is manual for now. Automating it (crates.io trusted publishing from GitHub Actions,
with no long-lived token) is a later change.

1. From a clean checkout of the release tag:

   ```sh
   git switch --detach v0.2.0
   cargo publish --workspace --locked --dry-run
   ```

   This packages every publishable crate in dependency order and builds each package as it would
   be built from crates.io. Crates with `publish = false` are skipped.
2. Publish with a crates.io API token that is scoped to `publish-update` for the `seaworthy*`
   crates and has a short expiry, kept out of CI and shell history (for example
   `cargo login` reading it from a password manager):

   ```sh
   cargo publish --workspace --locked
   ```

3. Check every crate's page on crates.io and its docs.rs build, then revoke or let the token
   expire.

**Bad release.** Yank the affected versions (`cargo yank --version 0.2.0 <crate>`), publish a
fixed patch release, and for a vulnerability publish a GitHub security advisory (and a RustSec
advisory) per [SECURITY.md](../SECURITY.md).

## MSRV policy

- The minimum supported Rust version is `workspace.package.rust-version` in `Cargo.toml`
  (currently 1.98). CI checks it on exactly that version (`x.y.0`) by building every library and
  binary target with all non-FIPS features.
- The MSRV moves only on purpose: when a language or library feature, or a required dependency,
  needs it. Before 1.0 it may rise in a minor release, never in a patch release. The release
  notes state every change.
- The workspace uses Cargo's MSRV-aware resolver (`resolver = "3"`), so lockfile updates prefer
  dependency versions that support the MSRV. A dependency that requires a newer Rust is a
  reason to wait or to raise the MSRV deliberately, not something to discover in CI.
- Dev-dependencies may require a newer toolchain than the MSRV: the MSRV check does not build
  tests.

## Toolchain bumps

The development toolchain is pinned to an exact stable release in `rust-toolchain.toml`. A new
release brings new lints, rustdoc rules and codegen, so it is a reviewed change of its own.
Dependabot proposes it weekly (the `rust-toolchain` ecosystem); a bump by hand follows the same
steps.

1. Change `channel` in `rust-toolchain.toml`, and nothing else in that pull request except fixes
   for what the new toolchain reports.
2. Run every check in [CONTRIBUTING.md](../CONTRIBUTING.md) plus the fuzz replay
   (`cargo test --manifest-path fuzz/Cargo.toml`), fix new clippy and rustdoc findings, and get
   CI green on Linux, Windows and macOS.
3. Leave `workspace.package.rust-version` alone unless the MSRV is raised on purpose (see
   above); raising it is a separate commit that says why.

**The fuzz nightly** is pinned in `fuzz/rust-toolchain.toml` and bumped the same way
(Dependabot proposes it). Check a new nightly with `scripts/fuzz.sh smoke` locally, or by running
the Fuzz workflow manually on the branch.

**GitHub Actions** are pinned to full commit SHAs with the version in a comment, and Dependabot
proposes updates after a seven-day cooldown. To pin by hand, resolve the tag and use the commit it
points at (for an annotated tag, the `^{}` line):

```sh
git ls-remote https://github.com/actions/checkout 'refs/tags/v7.0.1*'
```

**CI tools** (cargo-deny, cargo-fuzz, actionlint, zizmor, shellcheck) are pinned release binaries
in `scripts/ci/install-tool.sh`. To bump one, change its version, URLs and SHA-256 digests
together, taking each digest from the release's published checksums and confirming it with
`sha256sum` on the downloaded file; for cargo-fuzz, also change `CARGO_FUZZ_VERSION` in
`scripts/fuzz.sh`.

**Runner images** are pinned by label (`ubuntu-24.04`, `ubuntu-24.04-arm`, `windows-2025`,
`macos-15`), never `-latest`. Move to a newer image deliberately, before GitHub retires the old
one, in a pull request that touches only the labels.
