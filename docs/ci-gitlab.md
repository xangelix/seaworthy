# GitLab CI templates

Include-able GitLab CI for products packaged with seaworthy: a tag goes to verified, signed packages,
the APT, DNF and pacman repositories and the update helper's release tree on an S3-compatible store,
built from the product's `seaworthy.toml`. Products set inputs; they never copy a build or packaging
script. The templates live in [`ci/gitlab/`](../ci/gitlab/):

| File | What |
|---|---|
| `seaworthy.yml` | prepare, the Linux build, package, repo, publish, and the release-ordering lint |
| `seaworthy-windows.yml` | the Windows build and, for `msi` outputs, the MSI built with WiX and adopted; for products with `msi` or `zip` outputs |
| `seaworthy-macos.yml` | the macOS build and its ad hoc-signed dmg (or, for a service, unsigned pkg) on a Mac runner, for products with `dmg` or `pkg` outputs: a pipeline artifact, never part of a release |

They need GitLab 17.0 or later (`include` with `inputs`, array inputs). The packaging itself is
described in [packaging.md](packaging.md), the files the jobs read in
[configuration.md](configuration.md).

## Using them

Include the templates from a mirror of seaworthy in your GitLab instance (`project:`), or by URL
(`remote:`, pinned to a commit), at the seaworthy revision the product builds against. The prepare
job builds the `seaworthy` binary from a seaworthy checkout at that same revision, which
`seaworthy-fetch` puts in `seaworthy-dir` when it isn't there.

```yaml
include:
  - remote: https://raw.githubusercontent.com/xangelix/seaworthy/<commit>/ci/gitlab/seaworthy.yml
    inputs:
      tools-image: <an image with Rust and the packaging tools>
      seaworthy-fetch: >-
        git init -q .seaworthy && git -C .seaworthy fetch -q --depth 1
        https://github.com/xangelix/seaworthy.git <commit> && git -C .seaworthy checkout -q FETCH_HEAD
      server-deploy-jobs: deploy-server
      client-deploy-jobs: deploy-web-console
      # On a release: a command prefix that fetches each step's credentials
      # from your secret store, exports them, and runs the rest.
      package-secrets: ci/with-secrets.sh release-signing --
      repo-secrets: ci/with-secrets.sh repository-signing --
      publish-secrets: ci/with-secrets.sh package-store --
  - remote: https://raw.githubusercontent.com/xangelix/seaworthy/<commit>/ci/gitlab/seaworthy-windows.yml
    inputs:                                   # only with msi or zip outputs
      windows-image: <an MSVC build image>
      windows-tags: [<your Windows runner's tags>]
      package-secrets: ci/with-secrets.sh release-signing --
  - remote: https://raw.githubusercontent.com/xangelix/seaworthy/<commit>/ci/gitlab/seaworthy-macos.yml
    inputs:                                   # only with dmg or pkg outputs
      macos-image: <your Mac runner's image>
      macos-tags: [<your Mac runner's tags>]
      seaworthy-fetch: <as above>

# The server deploys only after every client is published (the release order, below).
deploy-server:
  stage: deploy
  needs: [seaworthy-publish, deploy-web-console]
  rules:
    - if: $CI_COMMIT_TAG =~ /^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(alpha|beta|rc)(\.(0|[1-9][0-9]*))?)?$/
```

No image, runner tag or secret source has a default: `tools-image`, `windows-image`, `windows-tags`,
`macos-image` and `macos-tags` are required inputs, and GitLab refuses a pipeline that leaves one
out. The `*-secrets` inputs are the one hook for credentials: any command that fetches the named
secrets from your store (Vault, a cloud secret manager, CI/CD variables), exports them and runs the
rest works. If it logs in with the job's id token, add the `id_tokens` to the jobs it runs in; keys
merge into the template's jobs (an `extends:` in your file would replace the template's own):

```yaml
seaworthy-package:
  id_tokens:
    SECRET_STORE_ID_TOKEN: { aud: "<your role's audience>" }
seaworthy-repo:
  id_tokens:
    SECRET_STORE_ID_TOKEN: { aud: "<your role's audience>" }
seaworthy-publish:
  id_tokens:
    SECRET_STORE_ID_TOKEN: { aud: "<your role's audience>" }
```

Before the first release: protect the release tags (a release runs on a protected ref only),
restrict who may set pipeline variables (they override the templates' variables), and make the
pipeline a required merge check (the release-ordering lint fails the pipeline, not the merge,
otherwise).

Committed beside the CI file (none of them holds a secret):

- **`seaworthy.toml`**: the products ([configuration.md](configuration.md)). With
  `[defaults.repository]`, every publication also carries the repository package.
- **`signing.toml`**: the signers, by command or custody system. With keys held in a secret store,
  the step's secrets prefix hands them over in the environment and `signing.toml` names the
  variables:

  ```toml
  [[manifest]]
  algorithm = "ml-dsa-87"
  key-env = "ACME_RELEASE_KEY_HEX"       # the key's hex (ML-DSA-87: its seed)

  [openpgp]
  secret-key-env = "ACME_REPO_KEY_ASC"   # an armored, unprotected secret key
  key = "<its fingerprint>"
  ```

  `seaworthy` takes both out of its environment before it runs anything and imports the OpenPGP key
  into a private throwaway gpg home for the run. `repo` needs only the OpenPGP key, so give the repo
  step only that.
- **`publish.toml`**: the bucket and the public URL. Write `public-url` as a plain
  `public-url = "…"` line: the repo job reads it to fetch the last publication's plan. With a
  repository package it must be `[defaults.repository]`'s `url`.

**Including by URL.** The release-ordering lint reads the product's CI file offline, so it can't
fetch a `remote:` (or `project:`) include; the prepare job passes the template it installed with
`--include` instead, and the lint warns that it didn't read the remote include. The warning is
harmless when the template is the only thing included that way.

## Overriding a template job's needs

`seaworthy-prepare` runs in `.pre`, before every stage of yours. If an override gives it `needs:` on
one of your jobs (a job that fetches private sources, say), set its `stage:` too: your job's stage
or a later one, before `build-stage`. GitLab refuses to create a pipeline whose job needs a job in a
later stage ("need … is not defined in current or prior stages"), and then no job runs at all, not
even the lint that would have reported it. `needs` replaces the template's list, so keep the
template's own entries in yours. A product's own tests can check every need against the stages, with
the templates merged in (`seaworthy::ci_order::load` reads the configuration as GitLab does).

## Jobs

Every job runs one step of `scripts/ci/seaworthy.sh` (Windows: `seaworthy-build.ps1` and
`seaworthy-msi.ps1`); the YAML only wires them. Artifacts live under `seaworthy/`. On a release the
step installs its tools first, then runs its `seaworthy` call alone under the `*-secrets` prefix: the
credentials never reach a tool install, and outside a release the prefix isn't used, so a protected
secrets role never sees a branch pipeline. What a release's signing jobs trust is
[below](#what-a-release-trusts).

| Job | Stage | Runs | What |
|---|---|---|---|
| `seaworthy-prepare` | `.pre` | every pipeline | fetches the seaworthy checkout if `seaworthy-dir` lacks it, checks it's the included template's revision (a marker both carry), builds `seaworthy` from it (outside the product's tree, with none of its build settings; its target directory cached for pipelines that aren't releases, while a release restores no cache and compiles afresh), checks `seaworthy.toml` and the release version, runs the `build-metadata` command (the only job that does), writes each target triple's build plan, runs the release-ordering lint, and hands on `seaworthy` and the scripts (for the build jobs and the pipelines that don't sign) |
| `seaworthy-build-linux` | `build-stage` | every pipeline | the Linux build plan in `build-image`: the launcher and helper once, each core once per CPU target in its own target directory, `strip = false` |
| `seaworthy-build-windows` | `build-stage` | when included | the Windows build plan on the Windows runner, natively, in the x64 MSVC developer environment it enters itself (vswhere, then `vcvarsall.bat x64`). Every build links the C runtime statically. The cores' sidecars come from the first CPU target's build and go beside every core |
| `seaworthy-package` | `package-stage` | every pipeline | `seaworthy package --platforms linux,windows`: signed on a release (the version from the tag or `version-file`, the sequence `CI_PIPELINE_IID`, the build metadata prepare recorded in `release.env`); on a dev build, its Windows binaries Authenticode-signed alone; unsigned otherwise (the `version-file`'s version, or `0.0.0-alpha`). On a release or a dev build it runs from seaworthy's own checkout, fetched afresh, and builds the tool itself |
| `seaworthy-msi` | `package-stage` | when included | WiX v5.0.2 on the Windows runner (installed from its pinned, hash-checked MSI unless the image has it): each product's `.wxs` built against the package job's signed tree, then `wix msi validate` (every ICE error fails the job). Unsigned |
| `seaworthy-msi-adopt` | `package-stage` | when included | `seaworthy adopt-msi` per MSI, on Linux with `tools-image`: its payload must be exactly the signed tree, and its security-relevant tables exactly what the `.wxs` declares; then signed with the package job's signers on a release, or `[authenticode]` alone on a dev build, all listed in `seaworthy/adopted/`. On a release or a dev build it runs from seaworthy's own checkout, as the package job does |
| `seaworthy-macos` | `build-stage` | when included | on the Mac runner, one at a time in `macos-resource-group`: fetches the checkout as prepare does, carries out the aarch64-apple-darwin build plan, builds `seaworthy` there and runs `seaworthy package --platforms macos`. Its packages land in `seaworthy/dist-macos/`, a pipeline artifact no later job takes: never signed and given no secrets, on a release too |
| `seaworthy-repo` | `publish-stage` | release | from `seaworthy/adopted/` when the MSI jobs ran, else the package job's packages: `seaworthy repo` with `--previous` = the plan at `public-url` (a 404 is the first publication; any other failure stops the job), from seaworthy's own checkout |
| `seaworthy-publish` | `publish-stage` | release, one at a time | `seaworthy publish` to the bucket in `publish.toml`, credentials from `publish-secrets`, from seaworthy's own checkout. With `SEAWORTHY_PUBLISH_DRY_RUN=1` (a pipeline variable) it checks the files, the store and the public URL and uploads and deletes nothing; the product's deploy jobs run on the release rule regardless, so a dry run on a pipeline that deploys must skip them itself |

**The release's name reaches the build.** The prepare job records the release's version and build
metadata in `seaworthy/release.env`: the tag without its `v`, else the `version-file`'s version,
else `0.0.0-alpha` outside a release; the `build-metadata` command's output, else the commit's short
SHA. That is exactly what the package job names it. The build steps export them to cargo as
`SEAWORTHY_RELEASE_VERSION` and `SEAWORTHY_RELEASE_BUILD`, and the package job refuses binaries built
for another release. A product whose server gates clients by version compiles its version token from
them (`v<version>+<build>`), so a client its new server refuses asks its helper for a release that
exists.

**Dev builds.** Outside a release, a pipeline `dev-sign-if` matches signs its Windows binaries, and
the MSIs, with `signing.toml`'s `[authenticode]` and nothing else: no manifest, so the update helper
never installs it, and no OpenPGP signature, so `repo` refuses it. The `seaworthy` call runs under
`dev-sign-secrets`, which should give the Authenticode credentials alone. `dev-sign-if` must name
protected refs only (the script refuses a dev build elsewhere), such as
`$CI_COMMIT_REF_PROTECTED == "true" && $CI_COMMIT_BRANCH != $CI_DEFAULT_BRANCH`. The default matches
nothing.

**CI test builds.** Outside a release, with `ci-signing-toml` set, every pipeline signs its
manifests and its rpm and pacman packages with the CI test keys that file names
(`seaworthy package --ci-test-signing`; `seaworthy.toml`'s `[defaults.ci-test-keys]`): public keys
kept in the product's repository, which only its non-release builds trust, so an installed dev
build's helper updates to a later one and a release's never does. The keys are copied into a private
directory first (git checks files out readable by everyone, and `seaworthy` signs only with key
files no one else can read). `repo` refuses such a build; a release never uses it.

**A release with no signer** (`SEAWORTHY_UNSIGNED=1`, as the GitHub workflow sets when it was handed
no secret) fails, unless `SEAWORTHY_ALLOW_UNSIGNED=1` says an unsigned one is meant; then it goes on,
with a warning, and the repositories refuse it.

**The CI test-key switch.** A product's non-release lanes may build helpers that trust its CI test
keys: seaworthy-formats' build switch, `SEAWORTHY_ALLOW_CI_TEST_KEYS=1`, set as a variable on the
build jobs. Every step of a release (the Windows build and MSI scripts too) fails when it's set to
anything but empty or `0`, and a release's package job refuses any built binary carrying the
switch's marker; `seaworthy verify` refuses them as well.

**The checkout is trusted as the job's own.** An image may run as another user than the one owning
the job's checkout, which git refuses as "dubious ownership". In GitLab CI the steps trust the job's
own clone (`safe.directory` for `$CI_PROJECT_DIR`, in git's command scope through
`GIT_CONFIG_COUNT`, for the step's processes only), so the tool installers and `SOURCE_DATE_EPOCH`
can read it.

## What a release trusts

The jobs that sign on a release (`seaworthy-package`, `seaworthy-msi-adopt`, `seaworthy-repo`,
`seaworthy-publish`; the package and adopt jobs on a dev build too) run no product code and trust
nothing earlier jobs left them but data:

- **seaworthy and its scripts are their own.** Each runs `seaworthy-fetch` afresh (removing any
  `seaworthy-dir` already there), checks the checkout is the included template's revision, runs that
  checkout's `seaworthy.sh` and builds `seaworthy` from it. The prepare job's `bin/` and `scripts/`
  (which the product's `build-metadata` command could have touched) serve the build jobs and the
  pipelines that don't sign; from it a release takes only `release.env` (read strictly, never
  sourced) and the plans.
- **Nothing comes from a cache.** The signing jobs restore none (`cache: []`, whatever the product's
  `default:` says), and seaworthy-prepare doesn't restore its own on a release: any pipeline can
  write any cache key, protected branches' included. seaworthy compiles from a copy of its checkout
  outside the product's tree (no product `.cargo/config.toml` or `rust-toolchain.toml`), with the
  system's basics alone in its environment (no `RUSTC_WRAPPER`, `CARGO_*`, `RUSTFLAGS`,
  `RUSTUP_TOOLCHAIN` or `CC`), into a new target directory.
- **Credentials reach the `seaworthy` call alone.** The `*-secrets` prefix wraps that call only; and
  credentials already in the job's environment (an `id_tokens` token, a cloud credential, the
  job token, a `key-env` variable `signing.toml` names, any name in `SEAWORTHY_HELD_ENV`) are taken
  out of it as the step starts and handed to that call alone. `seaworthy` itself gives its child
  tools an allowlisted environment, so only signing commands see a credential.

## Inputs

`seaworthy.yml`:

| Input | Default | Meaning |
|---|---|---|
| `tools-image` | **required** | prepare, package, repo, publish (and the MSI adoption): Rust, bash, curl and git, plus dpkg, rpm's `rpmsign` and `rpmkeys`, `createrepo_c`, pacman's `repo-add`, gnupg, libarchive's `bsdtar`, msitools (the MSI adoption) and desktop-file-utils (desktop products). On Arch Linux the steps install what's missing with pacman. Nothing it compiles ships |
| `build-image` | the official `rust:1.99.1-bookworm` image, digest-pinned | the Linux build; its glibc (Debian 12's 2.36) must be at or below the products' floor (2.34 by default, which a Debian 12 build meets) |
| `seaworthy-toml`, `signing-toml`, `publish-toml` | `seaworthy.toml`, `signing.toml`, `publish.toml` | the three files above |
| `ci-signing-toml` | (none) | outside a release, the CI test keys' signing configuration; empty, non-release builds stay unsigned |
| `seaworthy-dir` | `.seaworthy` | a seaworthy checkout at this template's revision |
| `seaworthy-fetch` | (none) | a command putting it there when it's missing (a shallow fetch of the commit, a submodule update) |
| `manifest` | `Cargo.toml` | the workspace the products build from; `seaworthy.toml`'s crate paths (`launcher`, `helper-crate`) are relative to its directory |
| `cargo-args` | (none) | more cargo arguments for every build (`--features fips`) |
| `version-file` | (none) | a `Cargo.toml` whose `[package]` version (read as TOML; a workspace-inherited one resolved) names a release that has no tag and every pipeline outside a release; a release tag must name the same version. A `SEAWORTHY_VERSION` pipeline variable overrides both |
| `build-metadata` | (none) | a command (`bash -eo pipefail`, in the checkout) printing the release's build metadata (SemVer's: dot-separated `[0-9A-Za-z-]` identifiers, at most 64 characters), for a product that composes its own version token. It runs in prepare alone, before anything is staged: the build and package jobs read what it printed from `release.env`, so product code never shares a job with the signers. Without it, the commit's short SHA |
| `release-if` | a `vX.Y.Z[-alpha\|beta\|rc[.N]]` tag | the rules expression for a release; the server deploy needs the same |
| `dev-sign-if`, `dev-sign-secrets` | never, (none) | a dev build (above); pass the same values to `seaworthy-windows.yml` |
| `build-stage`, `package-stage`, `publish-stage` | `build`, `build`, `deploy` | stages the product's `stages:` has |
| `server-deploy-jobs` | (none) | the server deploy jobs, comma-separated, for the lint |
| `client-deploy-jobs` | (none) | other client jobs every server deploy waits for (a web console's deploy) |
| `package-secrets`, `repo-secrets`, `publish-secrets` | (none) | on a release, a command prefix (space-separated words, no quoting or globbing) the step's `seaworthy` call runs under, giving it its credentials (`publish-secrets`: `SEAWORTHY_S3_ACCESS_KEY_ID` and `SEAWORTHY_S3_SECRET_ACCESS_KEY`) |

`seaworthy-windows.yml`:

| Input | Default | Meaning |
|---|---|---|
| `windows-image` | **required** | the MSVC build image: Visual Studio Build Tools with the MSVC x64 tools (and the C++ Clang tools, or `LIBCLANG_PATH`, for a FIPS core's bindgen), CMake, Go, NASM and rustup. `SEAWORTHY_VSWHERE` names vswhere.exe for an image that keeps it elsewhere |
| `windows-tags` | **required** | the Windows runner's tags |
| `build-stage`, `package-stage` | `build`, `build` | as `seaworthy.yml`'s |
| `package-secrets`, `dev-sign-secrets` | (none) | the adopt job's prefixes: pass the same values as to `seaworthy.yml` (the MSI is signed with the package job's signers) |
| `manifest`, `cargo-args` | as `seaworthy.yml`'s | the Windows build's |
| `release-if`, `dev-sign-if` | as `seaworthy.yml`'s | pass the same values |

`seaworthy-macos.yml`:

| Input | Default | Meaning |
|---|---|---|
| `macos-image` | **required** | the Mac runner's image: Xcode's command line tools (`codesign`, `hdiutil` and `pkgbuild` come with macOS), rustup, CMake and Go for a FIPS core, and Homebrew (the job installs Homebrew's bash: `seaworthy.sh` needs bash 4.4, and macOS ships 3.2) |
| `macos-tags` | **required** | the Mac runner's tags |
| `macos-resource-group` | `seaworthy-macos` | the job's resource group: a Mac host runs few VMs at once, so share it with any other Mac job of the project |
| `seaworthy-dir`, `seaworthy-fetch`, `manifest`, `cargo-args`, `release-if`, `build-stage` | as `seaworthy.yml`'s | the Mac job builds `seaworthy` from the checkout too, so it fetches it the same way; on a release it names the release's version (its packages still stay out of the release) |

**A compiler cache** is the product's own: set `RUSTC_WRAPPER` (and whatever credentials the cache
needs) as CI/CD variables for the build jobs. seaworthy's own build ignores it, whatever its scope
(the tool compiles with the system's basics alone in its environment, outside the product's tree,
so neither a project-wide `RUSTC_WRAPPER` nor the product's `.cargo/config.toml` reaches it). A
release should compile the product without it too, from source: what ships must not depend on what
another pipeline left in a cache.

**Product flags** belong in `.cargo/config.toml`'s `target.<triple>.rustflags` (or
`target.'cfg(…)'.rustflags`), which join the per-CPU flags. Cargo ignores `build.rustflags` once any
target flags are set, so `build-plan` refuses it in the repository's cargo configuration, and the
build refuses `RUSTFLAGS` and `CARGO_BUILD_RUSTFLAGS`, which would replace or drop the per-CPU flags.
Flags that only CI should add (profile-guided optimization's `-Cprofile-use`, say) go in the build
jobs' `SEAWORTHY_RUSTFLAGS` and `SEAWORTHY_CORE_RUSTFLAGS` variables
([packaging.md](packaging.md#extra-build-flags)); set them on the template's jobs in the product's
CI (GitLab merges a job's `variables`), and any other environment a build needs the same way:

```yaml
seaworthy-build-linux:
  variables:
    SEAWORTHY_CORE_RUSTFLAGS: -Cprofile-use={workspace}/pgo/{triple}.profdata
```

The builds remap the source paths rustc writes into the binaries (the workspace, the target
directories, the cargo home, each git dependency's checkout) to neutral ones, so a binary names no
runner path or private repository ([packaging.md](packaging.md#source-paths));
`SEAWORTHY_REMAP_PATHS: "0"` on the build jobs turns that off.

## The release order

A version gate sends every client looking for the server's version the moment the server deploys,
so packages, manifests and indexes, and any web console, must be out first. The prepare job's lint
(`seaworthy ci-order`, GitLab CI only) reads the product's CI (its local includes and this template)
and refuses unless each `server-deploy-jobs` job needs `seaworthy-publish` and each
`client-deploy-jobs` job, directly or through needs of needs, never with `optional: true`; no client
job may be allowed to fail, and no server job may run `when: always`. Stage order doesn't count: a
job a rule leaves out is skipped silently by stage order, while a `needs` on it fails the pipeline's
creation. A rule's `needs` replaces the job's when the rule matches, so every runnable rule must
leave the server needing the clients. An include with `rules:` is refused (the lint can't tell when
it applies), and globs match the repository's tracked files, as GitLab reads the commit. Run it
locally:

```sh
seaworthy ci-order --ci .gitlab-ci.yml --include .seaworthy/ci/gitlab/seaworthy.yml \
  --server deploy-server --client seaworthy-publish,deploy-web-console
```

A template passed with `--include` stands for an include whose inputs the lint can't see: its
inputs take their defaults, and those without one (the images and runner tags, which never decide an
order) read as empty.

## Windows signing

`seaworthy package` stamps each Windows binary's version resource and then signs it, so signing
stays on Linux, inside the package job (and the adopt job for the MSI): a signature made on Windows
before the stamp would break. Any Authenticode signer `signing.toml` can name works: osslsigncode
with a certificate and key, or a command. For Azure Artifact Signing (formerly Trusted Signing),
`scripts/ci/azure-sign.sh` (handed on by the prepare job as `seaworthy/scripts/azure-sign.sh`) signs
through jsign, pinned by SHA-256:

```toml
[authenticode]
command = ["bash", "seaworthy/scripts/azure-sign.sh",
           "--endpoint", "<region>.codesigning.azure.net",
           "--account", "<signing account>", "--profile", "<certificate profile>",
           "{file}"]
```

Nothing defaults the endpoint, account or profile. `package-secrets` gives it `AZURE_TENANT_ID`,
`AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET` (an app registration with the "Trusted Signing
Certificate Profile Signer" role on the profile) on a release: the secret reaches Microsoft Entra on
curl's standard input and the access token jsign through `env:`, never a command line. Instead of a
stored secret, `AZURE_FEDERATED_TOKEN_FILE` can name a federated identity token the registration
trusts (workload identity federation, such as GitLab's `id_tokens` written to a file); on GitHub
Actions, a job with `id-token: write` needs neither ([ci-github.md](ci-github.md#authenticode)). It needs a
Java 11+ runtime (the package step installs `jre-openjdk-headless` on an Arch tools image when
`signing.toml` names the script). Every signature is then checked against `seaworthy.toml`'s
`[defaults.authenticode]` pins, as with any signer; with Artifact Signing both the signer's chain
and its timestamp's end in Microsoft Identity Verification Root Certificate Authority 2020, so that
certificate is the trust file.

A signed release with Windows outputs refuses to package without `[authenticode]`: unsigned
executables are what SmartScreen, AppLocker and WDAC block. Non-release pipelines build them
unsigned (or Authenticode-signed alone, on a dev build).

The Windows runner is trusted for a release: `seaworthy-build-windows` builds the binaries the
package job signs (natively, for the FIPS module). The MSI it builds is checked before it's signed:
its payload must be exactly the signed tree, and its security-relevant tables (custom actions,
services, registry values, ACLs, shortcuts, the sequences, upgrades) exactly what the `.wxs` declares,
with none of the tables that run code at install time (`Binary`, `SelfReg`, COM registration,
embedded UI or chainers). Give release pipelines a Windows runner you'd trust with the binaries.

## FIPS products

The AWS-LC FIPS module is C, compiled during the build: it needs clang, CMake, Go and Perl, which the
stock Rust image lacks, and the image's glibc must be at or below the products' floor, or the
binaries won't start on the oldest supported systems. Build such an image (Debian 12 with the
module's pinned toolchain suits a 2.34 floor; see [fips.md](fips.md)), push it to a registry your
runners can pull from, and set:

- `build-image` to that image, digest-pinned;
- `cargo-args: --features fips` (or whatever enables it in your workspace);
- `fips = true` in `seaworthy.toml` (`verify` then checks every Linux core for the module), and the
  module's sidecars for Windows and macOS outputs.

Set the module's build switches (`AWS_LC_FIPS_SYS_CC=clang`, `AWS_LC_FIPS_SYS_USE_SYSTEM=0`) in the
image and in the product's own `.cargo/config.toml`.

## Requirements

- GitLab 17.0 or later. A seaworthy checkout reachable from the jobs (`seaworthy-fetch`), and the
  templates reachable at pipeline creation (a mirror, or a `remote:` URL).
- The Linux build image needs Rust and bash; the tools image Rust, bash, curl, git and the packaging
  tools (on Arch the rest installs itself).
- The Windows image needs PowerShell 5.1 and internet access to fetch WiX's pinned MSI, unless it
  carries WiX v5.0.2.
- The Mac needs macOS 11 or later on Apple Silicon, Xcode's command line tools, rustup, CMake and Go
  for a FIPS core, and Homebrew. The job writes cargo's target directories and the bundle under
  `$HOME` (on a VM, its own disk: copies on a shared mount of the build directory can come back
  incomplete).
- Linux jobs carry no tags: any Linux runner takes them.
