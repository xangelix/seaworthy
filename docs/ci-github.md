# GitHub Actions

A reusable workflow for products packaged with seaworthy: the product's `seaworthy.toml` to verified,
signed packages for Linux, Windows and macOS on GitHub-hosted runners, and optionally a publication
to an S3-compatible store. It runs the same steps as the GitLab templates
([ci-gitlab.md](ci-gitlab.md)): `scripts/ci/seaworthy.sh`, `seaworthy-build.ps1` and
`seaworthy-msi.ps1`, with a little GitHub glue (`scripts/ci/github.sh`). The packaging itself is
described in [packaging.md](packaging.md), the files the jobs read in
[configuration.md](configuration.md).

| File | What |
|---|---|
| `.github/workflows/dist.yml` | the reusable workflow (`on: workflow_call`) |
| `.github/actions/setup-seaworthy` | a composite action building the `seaworthy` command from a seaworthy checkout, cached by its commit |

## Calling it

Pin the workflow by its **full commit SHA**, never a branch or tag: the SHA is what you reviewed, and
the workflow builds the `seaworthy` command from that same commit (it checks out
`job.workflow_repository` at `job.workflow_sha`, the called workflow's own repository and commit,
and caches the tool under that SHA). seaworthy publishes no binaries yet; the commit is the version.

```yaml
# .github/workflows/release.yml
name: Release
on:
  push:
    tags: ["v*"]
  pull_request:

permissions: {}

jobs:
  dist:
    uses: xangelix/seaworthy/.github/workflows/dist.yml@<full commit SHA> # <what it is, e.g. main of 2026-10-26>
    permissions:
      contents: read
      id-token: write # the signing jobs request it (Azure Artifact Signing through OIDC)
    with:
      release: ${{ startsWith(github.ref, 'refs/tags/v') }}
      environment: release            # its protection rules gate signing and publishing
    secrets: inherit                  # or name each secret (below)

  upload:
    needs: dist
    runs-on: ubuntu-24.04
    permissions:
      contents: read
    steps:
      - uses: actions/download-artifact@<sha> # v8.x
        with:
          name: ${{ needs.dist.outputs.packages-artifact }}
          path: packages
      - run: cd packages && sha256sum --check SHA256SUMS
```

Each signer below is used only when its secrets or inputs are given. Outside a release (or a dev
build) the packages are unsigned, or signed by the CI test keys (`ci-signing-toml`). A release or a
dev build that is handed no signer at all fails, so a misnamed secret can't quietly ship unsigned
packages; pass `allow-unsigned: true` to build one unsigned on purpose (a warning; the repositories
refuse it, so nothing is published).

**The packages artifact** (`<artifact-prefix>-packages`, the `packages-artifact` output) holds
`packages/<product>/` (the Linux and Windows packages, with every MSI adopted) and
`packages-macos/<product>/`, each with its `packages.json` listing, the release manifests and SBOMs
next to the packages, and `SHA256SUMS` over everything. The verify job copies every listed file and
checks its SHA-256 against the listing; nothing unlisted is in it.

## Jobs

| Job | Runner | What | Permissions |
|---|---|---|---|
| `prepare` | Linux | seaworthy built at the workflow's commit (`setup-seaworthy`, cached by the SHA; compiled from source on a release or a dev build), `seaworthy check`, the release named (version, sequence, build metadata: the one job that runs the `build-metadata` command), the build plans and the build matrix | `contents: read` |
| `build-linux` | Linux | one job per target directory: the launcher and helper (`base`), each CPU's core; inside `linux-build-image`, whose glibc is the products' floor or older | `contents: read` |
| `build-windows` | Windows | the same, natively with MSVC (`seaworthy-build.ps1`) | `contents: read` |
| `build-macos` | macOS | the same, on Apple Silicon | `contents: read` |
| `package` | Linux | `seaworthy package --platforms linux,windows`: verify, layout, version resources, Authenticode, packages, manifests, SBOMs; signed on a release | `contents: read`, `id-token: write` |
| `msi` | Windows | WiX v5.0.2 (pinned, checksum-verified) builds and validates each MSI from package's `.wxs` | `contents: read` |
| `adopt-msi` | Linux | `seaworthy adopt-msi`: each MSI's payload checked against the signed tree and its security-relevant tables against the `.wxs`, signed, listed | `contents: read`, `id-token: write` |
| `package-macos` | macOS | `seaworthy package --platforms macos`: the dmg (desktop) or pkg (service), Developer ID-signed and notarized on a release with the Apple secrets, else ad hoc-signed | `contents: read` |
| `verify` | Linux | every listed artifact against its listing; the packages artifact with `SHA256SUMS` | `contents: read` |
| `publish` | Linux | on a release with `publish-toml`: `seaworthy repo` after the last published plan, then `seaworthy publish` (one at a time) | `contents: read` |

Every job declares its own permissions; the workflow's default is none. Linux jobs run
step-security's harden-runner in audit mode; every action is pinned by commit SHA; no checkout keeps
credentials. The build jobs never see a secret.

### What the signing jobs trust

The jobs that hold secrets (`package`, `adopt-msi`, `package-macos`, `publish`) run no product code
and take nothing from the jobs that do but data:

- **The tool and its scripts are their own.** Each checks seaworthy out at the workflow's commit and
  builds it there with `setup-seaworthy` (from source on a release or a dev build, never a cache),
  and runs `scripts/ci/seaworthy.sh` and `github.sh` from that checkout. The prepare job's
  artifact, which the product's `build-metadata` command could have touched, contributes only
  `release.env` (read strictly, never sourced) and the plans; its `bin/` and `scripts/` serve the
  build jobs alone. The `msi` and `verify` jobs run the checkout's scripts too.
- **The tool's own build sees nothing of the product's.** `setup-seaworthy` compiles a `git archive`
  of the commit under `RUNNER_TEMP`, outside the workspace (so no product `.cargo/config.toml` or
  `rust-toolchain.toml` applies), refuses a cargo configuration above it, and runs cargo with the
  system's basics alone in its environment: no `RUSTC_WRAPPER`, `CARGO_*` override, `RUSTFLAGS`,
  `RUSTUP_TOOLCHAIN` or `CC`.
- **Tools first, secrets after.** The packaging tools (apt packages, nFPM, osslsigncode built from
  its pinned source) install in a step that holds no secret. The secrets reach one step,
  `github.sh signed <step>`, whose signing material (`signing.toml`, the Authenticode PEM files, the
  Developer ID keychain) lives in a private directory under `RUNNER_TEMP` that is shredded (the
  keychain deleted) when that step ends, however it ends; an always-run step removes anything a
  cancelled run left. `seaworthy.sh` takes every credential out of its environment as it starts and
  hands it to the `seaworthy` call alone, and `seaworthy` gives its child tools (nFPM, strip, gpg,
  rpmsign, WiX, the macOS tools) an allowlisted environment, so only signing commands see a
  credential.
- **No secret in a file a later step reads,** and nothing through `GITHUB_ENV` but tool paths.

**Why the calling job grants `id-token: write`:** GitHub checks the permissions a called workflow's
jobs request against the caller's grant before it evaluates any condition, so the `package` and
`adopt-msi` jobs' `id-token: write` (for Azure Artifact Signing through OIDC) must be granted even
when no Azure input is set. The runner then puts the token-request variables
(`ACTIONS_ID_TOKEN_REQUEST_*`) in every step of those jobs: the tools steps unset them,
`seaworthy.sh` holds them back from everything but `seaworthy`, and `seaworthy` passes them to its
Authenticode signing command alone (`azure-sign.sh`, when the `azure-*` inputs are given). The
pinned actions those jobs use (checkout, the artifact actions, harden-runner) see them too: that is
GitHub's design, and why those jobs run no product code.

## Inputs

| Input | Default | What |
|---|---|---|
| `config` | `seaworthy.toml` | the product's seaworthy.toml |
| `manifest` | `Cargo.toml` | the workspace manifest the products build from |
| `products` | (every product) | the products to build and package, comma-separated; publishing needs every product |
| `platforms` | `linux,windows,macos` | the platforms to build |
| `release` | `false` | a release: versioned from the tag (or `version`, `version-file`), signed with the secrets given, published with `publish-toml` |
| `dev-sign` | `false` | outside a release: the Windows binaries and MSIs Authenticode-signed alone (never published) |
| `allow-unsigned` | `false` | let a release or a dev build that was handed no signer go on, unsigned, with a warning (otherwise it fails) |
| `ci-test-keys` | `false` | outside a release, build with seaworthy-formats' CI test-key switch (`SEAWORTHY_ALLOW_CI_TEST_KEYS=1`), so the product's helper trusts its CI test keys; package with `ci-signing-toml`. Refused on a release, by every step |
| `version`, `version-file`, `sequence`, `build-metadata` | the tag; none; `github.run_number`; the commit's first 8 characters | the release's name, as [ci-gitlab.md](ci-gitlab.md) describes `version-file` and `build-metadata` (a command) |
| `environment` | (none) | the GitHub environment `package`, `adopt-msi`, `package-macos` and `publish` run in on a release (or a dev build) |
| `signing-toml` | (generated) | your own `signing.toml` instead of the one generated from the secrets: command signers (a KMS), several manifest algorithms |
| `ci-signing-toml` | (none) | outside a release, the CI test keys' signing configuration (`seaworthy package --ci-test-signing`) |
| `publish-toml`, `publish-dry-run` | (none), `false` | on a release, the store to publish to; a dry run checks everything and uploads nothing |
| `toolchain` | the product's `rust-toolchain.toml` | a toolchain for the product's builds |
| `cargo-args` | (none) | more cargo arguments for every build (`--features fips`) |
| `rustflags`, `core-rustflags` | (none) | more rustflags for every build, and for the cores alone ([packaging.md](packaging.md#extra-build-flags); `{workspace}`, `{triple}` and `{cpu}` expand) |
| `build-env` | (none) | the builds' environment, JSON: `{"*": {"CC": "clang"}, "x86_64-pc-windows-msvc": {...}}` (a triple's entries win; the runner's, loader's and cargo's own variables are refused) |
| `linux-runner`, `windows-runner`, `macos-runner` | `ubuntu-24.04`, `windows-2025`, `macos-15` | runner labels (GitHub-hosted by default; the macOS one Apple Silicon) |
| `linux-build-image` | the official `rust:1.98.1-bookworm`, digest-pinned | the Linux builds' image: digest-pinned, glibc at or below the products' floor, a FIPS product's toolchain |
| `release-manifest-algorithm`, `openpgp-key-fingerprint`, `authenticode-timestamp-url`, `azure-*`, `apple-identity` | (none) | the signers' non-secret settings (below) |
| `artifact-prefix`, `retention-days` | `seaworthy`, `14` | the uploaded artifacts' names and lifetime |

Outputs: `version` (the release version) and `packages-artifact` (the packages artifact's name).

## Secrets and signers

The workflow generates `signing.toml` (names only, [configuration.md](configuration.md#signingtoml))
from whichever of these it is handed, in the step that signs and only on a release (Authenticode
also on a dev build). Secrets reach seaworthy through its environment (`key-env`, `secret-key-env`),
files only in a private directory (umask 077) shredded when the step ends, and are never printed or
put on a command line.

| Signer | Secrets | Inputs | Pins in seaworthy.toml |
|---|---|---|---|
| Release manifests | `RELEASE_MANIFEST_KEY` (hex) | `release-manifest-algorithm` | `release-signatures`, `release-keys` |
| rpm, pacman and repository signatures | `OPENPGP_SECRET_KEY` (armored) | `openpgp-key-fingerprint` | `openpgp-keys` |
| Authenticode, a certificate | `AUTHENTICODE_PFX` (PKCS#12, base64), `AUTHENTICODE_PFX_PASSWORD` | `authenticode-timestamp-url` | `[defaults.authenticode]` |
| Authenticode, Azure Artifact Signing | none (OIDC) | `azure-tenant-id`, `azure-client-id`, `azure-endpoint`, `azure-account`, `azure-profile` | `[defaults.authenticode]` |
| Apple Developer ID and notarization | `APPLE_CERTIFICATE_P12` (base64), `APPLE_CERTIFICATE_PASSWORD`, `APPLE_NOTARY_KEY` (.p8, armored or base64), `APPLE_NOTARY_KEY_ID`, `APPLE_NOTARY_ISSUER` | `apple-identity` (optional) | `[defaults.apple]` |
| Publishing | `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY`, `S3_SESSION_TOKEN` (optional) | `publish-toml` | `[defaults.repository]` |

A signed release refuses to run half-signed: with any signer, a product with Windows outputs needs
Authenticode, and a macOS package signed for a release needs the Developer ID (as the command
refuses, [packaging.md](packaging.md#signing)). Several manifest algorithms, a key in a KMS or an HSM
behind a command: pass your own `signing-toml` and the secrets your commands read.

**Keep the secrets in an environment.** Create an environment (`release`), restrict its deployment
branches and tags to your release tags, require reviewers if you like, store the secrets there under
the names above, and pass `environment: release`. A job that runs in an environment reads that
environment's secrets of the same names, in place of any the caller passed, so nothing outside a
reviewed release can reach them.

### Authenticode

**Azure Artifact Signing through OIDC (no stored secret):** register an app (or a user-assigned
managed identity) in Microsoft Entra, give it the "Trusted Signing Certificate Profile Signer" role
on the certificate profile, and add a federated credential for GitHub Actions: issuer
`https://token.actions.githubusercontent.com`, audience `api://AzureADTokenExchange`, subject
`repo:<owner>/<repo>:environment:release` (with `environment: release`; the subject must match the
job, which runs in that environment). Then set the five `azure-*` inputs; the tenant and client ids
are identifiers, not secrets. `azure-sign.sh` mints a fresh GitHub OIDC token for every signature
(the job's tokens expire within minutes) and exchanges it with Entra for the signing service's
token; neither reaches a command line. Pin `[defaults.authenticode]` to the profile's subject and
Microsoft Identity Verification Root Certificate Authority 2020.

**A certificate:** export it with its chain as PKCS#12, store it base64-encoded
(`base64 -w0 codesign.pfx`) as `AUTHENTICODE_PFX` with its password, and name an RFC 3161
timestamping service in `authenticode-timestamp-url` (your CA's). The job converts it to PEM files
for osslsigncode, built from its pinned source.

### Apple

Export the Developer ID Application identity (and, for a service's pkg, the Developer ID Installer
identity) with their keys as one PKCS#12, store it base64-encoded as `APPLE_CERTIFICATE_P12` with
its password; create an App Store Connect API key with the Developer role and store the `.p8` file,
its key id and issuer id. On a release the macOS packaging step imports the identities into a
keychain of its own (locked after two hours, deleted when the step ends; the PKCS#12's password
reaches `openssl` alone, through its environment, and each identity is re-wrapped under a throwaway
password for `security import`), stores the API key there as a `notarytool` profile, and
`seaworthy package --platforms macos` signs with the hardened runtime and a secure timestamp,
checks each signature against `defaults.apple.team-id`, notarizes, staples and asks Gatekeeper.
Without these secrets the macOS outputs stay ad hoc-signed (Gatekeeper refuses a downloaded copy).

## Build flags and environment

The cores build with `-C target-cpu=<cpu>` per job; your flags join after them:

```yaml
    with:
      core-rustflags: -Cprofile-use={workspace}/pgo/{triple}.profdata
      build-env: '{"*": {"CARGO_PROFILE_RELEASE_LTO": "fat"}}'
```

`RUSTFLAGS` itself is refused (it would replace the per-CPU flags); put permanent flags in
`.cargo/config.toml`'s `target.<triple>.rustflags`. A compiler cache (`RUSTC_WRAPPER`) is yours to
set through `build-env` for the product's builds (never seaworthy's own, which ignores it); a
release should build without one: what ships must not depend on what another run left in a cache.

## Pinning and updates

- Pin by full SHA with the version in a comment. Dependabot's `github-actions` ecosystem updates
  reusable-workflow pins like action pins.
- Moving the pin moves everything at once: the workflow, its scripts and the `seaworthy` command
  are one commit. A caller never mixes versions.
- The `setup-seaworthy` action can also be used on its own (its file shows how): check seaworthy out
  at the SHA you pin and point `source` at the checkout.
