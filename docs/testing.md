# Testing

seaworthy is tested at three levels:

- **Unit and integration tests** (`cargo test --workspace`), on Linux, Windows and macOS in the
  CI workflow, with the container suites (an S3-compatible store) in their own job.
  [CONTRIBUTING.md](../CONTRIBUTING.md) lists the checks to run before sending a change.
- **Fuzzing** of every parser of untrusted input ([fuzz/README.md](../fuzz/README.md)).
- **The lab**: the contract between what the `seaworthy` CLI packages and what the launcher and
  the update helper do with it, end to end, on real operating systems. This page describes it.

## The lab lanes

The lab runs in `.github/workflows/lab.yml` (Linux and macOS, this page) and `lab-windows.yml`
(Windows: [testing-windows.md](testing-windows.md)) on GitHub-hosted runners, on every pull
request, on pushes to `main`, weekly and on demand. The Linux and macOS lanes' required check is
**Lab result** (the Windows lab's is **Windows lab result**). The lanes share one fixture, the e2e workspace in
`crates/seaworthy-launcher/e2e/` (a launcher, per-CPU cores, the update helper `demo_helper`, the
lab server `conformance_server`), and one harness, [`seaworthy-lab`](../crates/seaworthy-lab/README.md):
a small TLS lab server that serves a release tree and the product's required-version endpoint,
a throwaway CA, and the client the fixture helper's version source uses.

| Lane (job) | What it proves | Script |
|---|---|---|
| Launcher e2e, Linux | The CPU records survive the shipped profile (LTO, strip); the launcher picks the right core natively and under qemu's CPU models (below the floor, v2, v3, AVX-512 masked); overrides, damage and pass-through; the glibc floor; the build-time refusals; `seaworthy verify` and `layout` accept the real binaries, refuse a swapped core, and the laid-out tree runs | `scripts/launcher-e2e.sh selection` |
| Launcher e2e, Linux FIPS | A per-CPU core with the AWS-LC FIPS module passes its power-on self-tests (stripped too); `seaworthy fips-check` and `scripts/verify-fips-binary.sh` agree; one flipped bit in the module aborts before product code runs | `scripts/launcher-e2e.sh fips` |
| Launcher e2e, macOS | The Mach-O records and selection on Apple Silicon; the CLI's disk image (mounts, verifies, runs), service pkg (payload, LaunchDaemons, scripts), a command-line tool's pkg (the tool directory, its signatures, its `PATH` link; the launcher runs from it) and a FIPS product shipping the module's dylib | `scripts/launcher-e2e-macos.sh` |
| Linux conformance | Real deb, rpm and pacman packages (built by the CLI, signed, published as signed APT, DNF and pacman repositories) installed by each distribution's package manager under systemd on Debian 13, Ubuntu 24.04, UBI 9, Fedora 43 and Arch: every lifecycle path, units and users, `systemd-analyze security`, a desktop product and its polkit rule, OpenPGP key rotation, foreign signatures refused; and the update flow through the real helper (refused releases, upgrades, a refused downgrade, an administrator's upgrade overtaking a held run, the helper removing itself) | `scripts/linux-conformance.sh` (the suite: `crates/seaworthy/tests/conformance.rs`) |
| macOS pkg install | The service pkg installed with sudo: launchd runs it and loads the helper's daemon; the helper upgrades, refuses a wrong format, a tampered pkg, a downgrade and an `off` or untrusted policy file, survives failing install scripts (backing off, then rolling forward); the uninstaller removes everything | `scripts/macos-pkg-install.sh` |
| Upgrade from previous, Linux | The previous lab build (the latest successful run on `main`) installed on the five distributions, then updated by its own helper to this run's build over TLS from the lab (a name-constrained throwaway CA in the system store, hosts entries): an `off` policy honored, another key's manifest refused, then the transition (version, the service restarted on the new build, the new files, the path unit untouched, the service's state kept) | `scripts/upgrade-candidate.sh linux`, `scripts/upgrade-previous.sh`, `scripts/upgrade-linux.sh` (the suite: `crates/seaworthy-lab/tests/upgrade_linux.rs`) |
| Upgrade from previous, macOS | The same on macOS: the previous pkg installed, the CA in the System keychain, the helper's daemon updating it to this run's pkg | `scripts/upgrade-candidate.sh macos`, `scripts/upgrade-previous.sh`, `scripts/upgrade-macos.sh` |
| Upgrade from previous, Windows (`lab-windows.yml`) | The same on Windows: the previous MSI installed, the CA in `LocalMachine\Root`, the helper's service updating it to this run's MSI through Windows Installer ([testing-windows.md](testing-windows.md#the-upgrade-lane)) | `scripts/windows-lab-build.ps1` (its upgrade step), `scripts/windows-upgrade-previous.ps1`, `scripts/windows-upgrade.ps1` |

### How the lab is built

- **Builds as a product's pipeline builds.** The fixture goes through `seaworthy build-plan` and
  the CI template's build step (`scripts/ci/seaworthy.sh build`), then `seaworthy package`,
  `sign` and `repo`. On Linux the binaries are built in the pinned Rust builder image (Debian 12:
  their glibc runs on every distribution of the lanes), offline, from crates vendored from the
  e2e lockfile, in an unprivileged container (`scripts/lib/lab.sh`).
- **The version source.** The helper takes its version from a caller closure. The fixture's
  closure asks the lab server's required-version endpoint (`GET /_lab/required-version`) through
  the update helper's own TLS construction (seaworthy-crypto's policy, the operating system's
  trust store). The conformance lanes run it on loopback over HTTP; the upgrade lanes over TLS
  under the names `updates.lab.invalid` and `packages.lab.invalid`.
- **Keys.** The conformance and pkg-install lanes generate throwaway keys every run. The upgrade
  lanes need one key across runs (a previous build's helper must trust this run's packages), so
  the fixture's builds are non-release builds signed with a **public CI test key** committed in
  `crates/seaworthy-launcher/e2e/desktop/keys/` (Linux and macOS) and
  `crates/seaworthy-launcher/e2e/scm/keys/` (Windows) (`--ci-test-signing`; the
  [threat model's CI test-key mechanism](threat-model.md#the-ci-test-key-mechanism)). The
  candidates' helpers trust it as a product's CI build would: as a CI test key beside the release
  key, through `ci_test_keys!` in a build made with `SEAWORTHY_ALLOW_CI_TEST_KEYS=1` (set for that
  build alone; the binary carries the CI test-key marker, which the candidate build checks and
  `seaworthy verify` accepts in a `--ci-test-signing` build only). Nothing but the fixture trusts
  it, and a helper that does only ever reaches names under `.invalid`, which never resolve outside
  a lab's hosts entries, or 127.0.0.1 (both helpers' build scripts refuse any other URL).
- **The throwaway CA** permits only the lab's names (critical name constraints), and its private
  key never leaves the process that made it, so nothing can issue another certificate under the
  root a lane trusts. The lanes remove it, the hosts entries and the installed product on every
  exit path.
- **The previous build.** The upgrade jobs on `main` keep their candidate as an artifact
  (`lab-upgrade-linux`, `lab-upgrade-macos`, 30 days; the Windows lab's build job keeps
  `lab-upgrade-windows`). A later run picks the latest successful run of the workflow on
  `main` (from a push, the schedule or a dispatch, never a pull request's; the repository's own;
  its commit on `main`, reachable from the branch's tip as the branches API reports it, so a run
  of a tag named `main` never counts; a lower run number, so an older release), downloads its
  artifact with the job's token
  (`actions: read`, nothing else), checks the zip against the SHA-256 digest GitHub recorded at
  upload and every file against the build's own listing. When there is none
  (the lane's first run on `main`, an expired artifact, or a build trusting a rotated test key),
  the lane is skipped with a warning and the run's candidate becomes the next one's previous
  build. It doesn't build a previous build from the merge base instead: at the lane's
  introduction the merge base has no lab fixture to build, and on every other run it would
  double the lane's cost for what the weekly schedule keeps available anyway.

### Running the lanes locally

| Lane | Locally | Needs |
|---|---|---|
| Launcher e2e, Linux | `scripts/launcher-e2e.sh selection` | x86-64 Linux; qemu-user (`QEMU_X86_64="$(scripts/ci-qemu.sh)"`) for the emulated CPUs; cargo-xwin for the Windows cross check (or `SEAWORTHY_LAUNCHER_E2E_WINDOWS=0`) |
| Launcher e2e, FIPS | `scripts/launcher-e2e.sh fips` | Clang, CMake, Go, Perl, nm, python3 |
| Launcher e2e, macOS | `bash scripts/launcher-e2e-macos.sh` | Apple Silicon, bash 4.4+, Xcode's command line tools |
| Linux conformance | `scripts/linux-conformance.sh build` builds the packages, repositories and `lane.json` | docker (an unprivileged builder container), gpg, rpm, dpkg-dev, createrepo_c, pacman's repo-add, bsdtar |
| macOS pkg install, upgrade lanes | **CI only** | they install system daemons and trust a CA machine-wide: run them in a throwaway VM |

`SEAWORTHY_LAUNCHER_E2E_REQUIRED=1` turns a launcher check that would skip (a missing tool)
into a failure, as CI sets it.

**CI only:** `scripts/linux-conformance.sh all` and `scripts/upgrade-linux.sh` boot systemd as
PID 1 in containers with `CAP_SYS_ADMIN` (never privileged; see
`crates/seaworthy-test-support/src/systemd.rs`). They are meant for a CI runner's own docker
daemon: don't run them against a daemon other workloads share. `scripts/macos-pkg-install.sh` and
`scripts/upgrade-macos.sh` install and remove system daemons, edit `/etc/hosts` and the System
keychain; `scripts/upgrade-previous.sh` and `scripts/windows-upgrade-previous.ps1` need the
GitHub Actions environment.
