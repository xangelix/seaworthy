# seaworthy

*Built artifacts in, verified install trees and packages out. Nothing compiles here.*

The seaworthy command-line tool, also usable as a library. It turns already-built artifacts and a
product's `seaworthy.toml` into every deliverable. A product ships one or more programs, each a
launcher plus one core per CPU target (`seaworthy-launcher`), optionally with an update helper
(`seaworthy-updater`).
`seaworthy` proves those binaries are what the configuration says, lays out each platform's install
tree, and builds every output from those trees:

- deb, rpm and pacman packages (through the pinned nFPM) with their systemd units, `sysusers.d`
  entry, preset and scripts;
- a Linux tarball and a Windows zip, written by seaworthy's own reproducible writers;
- the MSI's WiX source (and the MSI where WiX runs), and the Group Policy templates for the update
  policy;
- a macOS app bundle in a disk image, or, for a service, in a flat installer package.

It stamps a version resource into every Windows binary, signs what each platform verifies
(Authenticode, OpenPGP), and writes a signed release manifest and a CycloneDX SBOM beside every
installable artifact. `repo` then publishes every product's release as signed APT, DNF and pacman
repositories plus the release tree the update helper fetches from, with a publish plan; `publish`
uploads that plan to any S3-compatible store, in order, and checks it from the clients' side.

It never compiles product code, so a cargo or rustc change can't break it. Its only contact with the
toolchain is reading the records the compiler already wrote into each core (`seaworthy-levels`).

## Commands

```text
seaworthy check            [--config seaworthy.toml]
seaworthy verify           [--config seaworthy.toml] --artifacts DIR [--product ID] [--platforms LIST]
seaworthy layout           [--config seaworthy.toml] --artifacts DIR --out DIR [--product ID] [--platforms LIST] [--no-strip]
seaworthy package          [--config seaworthy.toml] --artifacts DIR --out DIR --release VERSION --sequence N
                           [--build METADATA] [--product ID|repository] [--platforms LIST] [--no-strip]
                           [--signing signing.toml] [--authenticode-only] [--ci-test-signing FILE]
seaworthy adopt-msi        [--config seaworthy.toml] --out DIR --product ID --msi FILE [--signing signing.toml]
                           [--authenticode-only] [--ci-test-signing FILE]
seaworthy repo             [--config seaworthy.toml] --packages DIR --out DIR --signing signing.toml
                           [--previous publish-plan.json] [--date EPOCH] [--allow-older]
seaworthy publish          --repo DIR --target publish.toml [--dry-run] [--no-prune]
seaworthy build-plan       [--config seaworthy.toml] --triple TRIPLE [--product ID] [--manifest Cargo.toml]
seaworthy ci-order         --ci .gitlab-ci.yml [--root DIR] [--include FILE,…] --server JOB,… --client JOB,…
seaworthy version          --release VERSION --sequence N [--json]
seaworthy manifest-version --manifest Cargo.toml
seaworthy keygen           --algorithm ml-dsa-87|ecdsa-p256|ed25519 --secret FILE --public FILE
seaworthy sign-statement   --algorithm ml-dsa-87|ecdsa-p256|ed25519 --key FILE [--raw]
seaworthy fips-check       FILE…
seaworthy glibc-check      [--floor X.Y] FILE…
```

| Command | What it does |
|---|---|
| `check` | Parses and validates `seaworthy.toml` (every service rendered for every platform). |
| `verify` | Checks the built artifacts against the configuration and reports every finding at once. |
| `layout` | `verify`, then each platform's install tree, stripped, with `layout.json`. |
| `package` | `verify` and `layout`, then every output, signed with `--signing`, listed in `packages.json`. |
| `adopt-msi` | Takes back an MSI WiX built on Windows from `package`'s `.wxs`: payload checked against the signed tree, its security-relevant tables against the `.wxs`, signed, listed. |
| `repo` | Every product's release as signed APT, DNF and pacman repositories, the release tree and `publish-plan.json`. |
| `publish` | Uploads what `repo` built to an S3-compatible store (feature `publish-s3`, on by default). |
| `build-plan` | The build steps one target triple needs: each program's launcher and the helper once, each program's core per CPU target. |
| `ci-order` | The release-ordering lint for **GitLab CI only**: every server deploy job waits for every client publication. |
| `version` | Every package format's spelling of a release version and sequence. |
| `manifest-version` | A `Cargo.toml`'s `[package]` version, read as TOML (a workspace-inherited one resolved). |
| `keygen` | A new release key: secret (hex, mode 0600) and public (hex), never over an existing file; prints the key id. |
| `sign-statement` | Signs a canonical release statement read on stdin: the reference command signer. |
| `fips-check` | `verify`'s FIPS symbol checks over single ELF files. |
| `glibc-check` | `verify`'s glibc floor over single ELF files (default 2.34). |

Exit codes: 0 success, 1 a refusal (invalid configuration, failed checks, a tool that failed), 2 a
usage error (an unknown, repeated, missing or inapplicable option). Without `--product`, `verify`,
`layout` and `package` cover every product. `--platforms` (comma-separated `linux`, `windows`,
`macos`) narrows them to those platforms' outputs and skips a product with none there.

```sh
seaworthy check --config seaworthy.toml
NFPM="$(scripts/ci/install-nfpm.sh)" SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" \
  seaworthy package --artifacts target/artifacts --out target/dist \
    --release 1.4.0-rc.2 --sequence 812 --signing signing.toml
seaworthy repo --packages target/dist --out target/repo --signing signing.toml \
  --previous last/publish-plan.json
SEAWORTHY_S3_ACCESS_KEY_ID=… SEAWORTHY_S3_SECRET_ACCESS_KEY=… \
  seaworthy publish --repo target/repo --target publish.toml
seaworthy version --release 1.4.0-rc.2 --sequence 812
# deb     1.4.0~rc.2-812
# rpm     1.4.0~rc.2-812
# pacman  1.4.0rc.2-812
# msi     1.4.0
```

As a library:

```rust,no_run
use std::path::Path;

let config = seaworthy::config::Config::load(Path::new("seaworthy.toml"))?;
let verified = seaworthy::verify::verify(&config, "agent", Path::new("target/artifacts"))?;
for tree in seaworthy::layout::layout(
    &config,
    "agent",
    &verified,
    Path::new("target/dist"),
    seaworthy::layout::Options::default(),
)? {
    println!("{}: {} files under {}", tree.triple, tree.files.len(), tree.install_root);
}
# Ok::<(), seaworthy::DistError>(())
```

## The rules

1. **Verify before anything ships, and report everything at once.** Every target has a core whose
   record names this platform, this CPU and only known features; the launcher's CPU list matches
   the targets, in order; Windows sidecars are byte-identical across target builds; every binary is
   the platform's format and kind; FIPS cores link only the pinned AWS-LC module; runtime
   dependencies are the base system's; no Linux binary needs a glibc newer than the floor. An
   import table or version table that doesn't parse is a finding, never a pass.
2. **The configuration is authoritative, and typos are errors.** `seaworthy.toml` refuses unknown
   keys, and a product's service is validated by `seaworthy-service`'s own renderers for every
   platform, so a file that loads is one every generator can package.
3. **One release version, spelled the same way everywhere.** A release is a version plus a
   sequence, and every package format orders releases exactly as the update helper's floor does.
   The pre-release grammar is narrowed until that holds (`-alpha`, `-beta`, `-rc`, each optionally
   `.N`); the tests prove it against the real `dpkg`, `rpm` and `vercmp`.
4. **Never delete what it didn't create; never ship what wasn't verified.** A staging directory is
   replaced only if it carries `layout`'s marker; a file that changed since `verify` read it, and
   two files landing on one install path, are refused.
5. **The same inputs give the same bytes.** Every timestamp is `SOURCE_DATE_EPOCH`, entries are
   sorted, owners are root, and with the pinned nFPM a rebuild is byte-identical (the tests build
   everything twice). The MSI and the dmg are the exceptions: WiX and `hdiutil` write fresh codes
   and timestamps.
6. **Package scripts run the lifecycle and nothing else, and the host's policy wins.** A fresh
   install applies the host's systemd preset policy through a vendor preset file; an upgrade
   restarts the service and never the update units (the helper may be running the upgrade);
   removal stops and disables, and state and the sandbox user stay. A masked unit is never touched.
7. **On Windows the installer does the work, declaratively.** The MSI installs to a fixed
   directory, applies the renderers' DACLs, registers the service and the helper, and grants the
   service only the right to start the helper. Its only custom actions run the system's `sc.exe`
   for the recovery settings, on a first install or an upgrade, never in a repair.
8. **A release manifest per artifact, signed only as the product's clients accept.** The signers
   must cover exactly `release-signatures`, hold one of `release-keys` and pass the update helper's
   key intake, and every signature is verified before it's written.
9. **Everything is signed for its platform, as `seaworthy.toml` pins.** Authenticode signatures are
   checked against `[defaults.authenticode]`, OpenPGP signatures against `openpgp-keys`, each as
   soon as it's made. A signed release with Windows outputs refuses to run without an Authenticode
   signer.
10. **No build environment in a package.** nFPM expands `$VAR` and WiX expands `$(…)`, so
    `seaworthy.toml` refuses `$` in every text that reaches a package.
11. **Publish only what every client accepts, and never change a published file.** `repo` checks
    each release as the clients will, signs the indexes, and, given the last publication's plan,
    refuses a build that would give an immutable path other bytes or isn't newer.
12. **The bucket is the truth.** `publish` checks everything before it uploads anything, uploads
    immutable files create-only, the indexes after them and the plan last (only over the version it
    read), reads every upload back by the store's checksum or its bytes, fetches the result through
    the public URL, and prunes only files no published plan has referenced for the retention
    period, never a file from before its first plan there.

The details are in [docs/packaging.md](../../docs/packaging.md).

## Environment

| Variable | Read by | Meaning |
|---|---|---|
| `NFPM` | `package` | The nFPM binary (default `nfpm`; `scripts/ci/install-nfpm.sh` installs the pinned 2.47.0). |
| `SEAWORTHY_WIX` | `package` | The WiX binary (v5.0.2). Unset, an `msi` output writes the `.wxs` for a Windows runner to build. Not `WIX`: WiX v3's installer sets that machine-wide. |
| `SOURCE_DATE_EPOCH` | `package`, `adopt-msi` | Every timestamp in every artifact (default 315532800, 1980-01-01; at most 4294967295). |
| `STRIP` | `layout`, `package` | The strip tool (default `strip`). |
| `MSIEXTRACT`, `MSIINFO` | `adopt-msi` | msitools' programs (default `msiextract`, `msiinfo`). |
| `DESKTOP_FILE_VALIDATE` | `package` | The menu-entry validator (default `desktop-file-validate`, when on `PATH`). |
| `SEAWORTHY_S3_ACCESS_KEY_ID`, `SEAWORTHY_S3_SECRET_ACCESS_KEY`, `SEAWORTHY_S3_SESSION_TOKEN` | `publish` | The store's credentials (the session token optional); never read from a file, never printed. |
| variables named by `signing.toml` | `package`, `adopt-msi`, `repo` | Keys a custody system hands over (`key-env`, `secret-key-env`), taken out of the environment before any tool runs. |
| `SEAWORTHY_TOOL_ENV` | every command running tools | More variable names (comma- or space-separated) the packaging tools get beside the system's own; never a `SEAWORTHY_*`, `ACTIONS_*`, `AZURE_*` or `AWS_*` one or a CI token, which only signing commands see. |
| `SEAWORTHY_REQUIRE_PACKAGE_TOOLS` | the tests | `1` turns a missing packaging tool (nFPM, dpkg, rpm, WiX, osslsigncode, …) from a loud skip into a failure. |
| `SEAWORTHY_BLESS` | the tests | `1` rewrites the golden files. |

## Features

| Feature | Adds |
|---|---|
| `publish-s3` (default) | `s3`, the S3 client (SigV4 over `seaworthy-crypto`, create-only checksummed puts, bounded reads), and `publish`. Without it the crate opens no network connection and the binary's `publish` refuses. |
| `conformance` | The Linux conformance lane's suite (`tests/conformance.rs`), run by the lane's own script against systemd containers; never part of the default build or the generic test jobs. |

A library caller that never publishes takes `default-features = false`.

## What it needs

- **To verify and lay out:** nothing but the artifacts and `strip`. Linux binaries arrive with
  their symbol tables (`strip = false`): `verify` reads them and `layout` strips the shipped copies.
- **To package:** nFPM 2.47.0 for deb, rpm and pacman; WiX v5.0.2 for the MSI (on Windows, or under
  Wine for local checks); macOS's own `codesign`, `hdiutil`, `pkgbuild` and `productbuild` for the
  macOS outputs, so those package on a Mac.
- **To sign:** osslsigncode 2.14 (Authenticode with a local certificate, and the check of every
  Authenticode signature; `scripts/ci/install-osslsigncode.sh` builds it from its pinned source),
  gpg, rpmsign and rpmkeys, or whatever programs `signing.toml`'s commands name.
- **To build repositories:** `dpkg-scanpackages` (dpkg), `createrepo_c` and `repo-add` (pacman;
  on Debian and Ubuntu, `pacman-package-manager` and `makepkg`, whose shell libraries `repo-add`
  loads), plus `dpkg-deb` and `bsdtar` to read the repository package back.
- **To adopt an MSI:** msitools' `msiextract` and `msiinfo`.

The artifact directory the build leaves for `seaworthy`:

```text
<artifacts>/<triple>/launcher/<executable>[.exe]     each program's
<artifacts>/<triple>/helper/<helper>[.exe]           when the helper ships
<artifacts>/<triple>/cores/<build>/lib<core>.so      Linux
<artifacts>/<triple>/cores/<build>/<core>.dll        Windows, beside the sidecars
<artifacts>/<triple>/cores/<build>/lib<core>.dylib   macOS
```

`<build>` is the CPU target, or `<cpu>.f<8 hex>` for a core built with cargo features of its own.

`build-plan` prints the build that fills it, and the GitLab templates carry it out.

## Scope

- **Building** is the CI's job: `build-plan` says what to build, the CI scripts run cargo.
- **Installing** goes through each platform's package manager or installer.
- **The bucket and its CDN** (creating them, their credentials and cache rules) are the operator's.
- **File associations, an installer UI and per-user installs** are out: the MSI is per-machine and
  silent or minimal.

## See also

- [docs/packaging.md](../../docs/packaging.md): outputs, layout, verify, signing, repositories,
  publishing.
- [docs/configuration.md](../../docs/configuration.md): the `seaworthy.toml`, `signing.toml` and
  `publish.toml` reference.
- [docs/ci-gitlab.md](../../docs/ci-gitlab.md): the GitLab CI templates.
- [docs/updates.md](../../docs/updates.md) and [docs/services.md](../../docs/services.md): what the
  packages install and how products update.
