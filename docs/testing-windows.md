# The Windows lab

How seaworthy tests its packaging-to-runtime contract on Windows: the products the seaworthy CLI
builds, installed by Windows Installer and run by the real Service Control Manager, on
GitHub-hosted `windows-2025` runners (an administrator, real NTFS DACLs, a throwaway machine per
job). The workflow is `.github/workflows/lab-windows.yml`; it runs on every pull request, on
pushes to `main`, weekly and on demand.

Make **Windows lab result** the required check. It fails unless the build and every lane below
passed; the FIPS lane is reported in its summary and never required.

## The fixture

`crates/seaworthy-launcher/e2e` (its own workspace and lockfile) holds the products:

| Member | What it is |
|---|---|
| `scm` | The launcher: plain x86-64, three cores in preference order (x86-64-v4, v3, v2). |
| `scm_core` | The service, one core per CPU target: seaworthy-service's run loop (`run_windows_service`), the update request API, a simulated version gate (`GET /required` on a loopback stub), and control files that make it fail on purpose. Its crate docs list the commands and the evidence files. |
| `scm_helper` | The update helper: seaworthy-updater's `helper::main` with a lane's `seaworthy.toml`, release key and URLs compiled in (`SEAWORTHY_E2E_HELPER_*`, `scm_helper/build.rs`), asking for the version through the lab's required-version client (`seaworthy-lab`'s `client`). The update lane's build asks the loopback stub (127.0.0.1:8470) and fetches the release from it; the upgrade lane's trusts the public CI test key alone and dials only the lab's names under `.invalid` over TLS. Its build script refuses any other URL: plain HTTP goes to 127.0.0.1 only, HTTPS to `.invalid` names only. |
| `demo`, `demo_core` | The desktop fixture's launcher and cores (also the Linux launcher lanes'). |

The products:

- `scm/seaworthy.toml`: `[product.scm]`, the SCM suite's service (`acme-e2e`, a virtual account,
  one 8 s restart action, no update helper), and `[product.agent]`, the update lane's service
  (`AcmeAgent`, a virtual account, its helper `AcmeAgent-update`, update policy `auto`, and a
  display name outside one Windows code page; its files hold `lab/build.txt`, the build's
  version token). It names `keys/release.pub` and `keys/codesign.pem`: the build copies it into
  its work directory and makes those keys there. Its `[defaults.ci-test-keys]` names
  `keys/ci-test.pub`, the upgrade lane's **public CI test key**, committed in `scm/keys/`
  ([the CI test-key mechanism](threat-model.md#the-ci-test-key-mechanism)): nothing but this
  fixture trusts it.
- `scm/seaworthy-fips.toml`: `[product.scm]` with its cores on the AWS-LC FIPS module
  (`fips = true`, the module's DLL as a Windows sidecar).
- `desktop/seaworthy.toml`: `[product.viewer]`, a desktop product with data files, an icon and
  shortcuts (no helper, unsigned).

## The build

`scripts/windows-lab-build.ps1` (PowerShell 7) builds everything natively on one runner and
leaves a bundle for the lanes:

1. **Pinned tools**, each checked against its SHA-256 before it runs: WiX 5.0.2 from its MSI
   (the version the CLI and the GitLab template build with, MS-RL; the hash matches WiX's
   published metadata), osslsigncode 2.14 from its Windows release (the hash GitHub records for
   the asset). The FIPS variant adds NASM 2.16.03 from nasm.us (which publishes no checksums;
   the pinned hash matches the one Scoop recorded for the same file independently) and checks
   that CMake, Go, Ninja and Visual Studio's clang (libclang, for bindgen) are on the image,
   with Ninja 1.13.2 from its pinned release when neither the image nor Visual Studio has it.
2. **The CLI and the lanes' binaries**, release builds of this workspace: `seaworthy`,
   seaworthy-service's `windows_scm_e2e` example (the version-gate stub and start/stop/status
   through the crate's backend) and its `windows_scm` test, seaworthy-crypto's
   `entropy_probe`, and seaworthy-updater's `windows_policy_live` test.
3. **Keys made for the run**: an ML-DSA-87 release key (`seaworthy keygen`) and a self-signed
   RSA-3072 code-signing certificate. The certificate carries `basicConstraints` critical
   `CA:FALSE`: Windows' Authenticode policy refuses a CA certificate as the signer
   (`TRUST_E_BASIC_CONSTRAINTS`), which is what a plain `openssl req -x509` makes. Its subject
   is one RDN, so it reads the same in every tool's order. Only the certificate leaves the job.
4. **The products, built by the build plan**: `seaworthy build-plan`, carried out by
   `scripts/ci/seaworthy-build.ps1` (the GitLab template's Windows build step), every cargo
   target directory under a short root (`C:\swl`): the FIPS module's CMake build nests deep, and
   Windows caps an object path at 250 characters.
5. **Packages, by `seaworthy package` with `SEAWORTHY_WIX`**: the SCM product 1.0.0; the agent
   1.0.0-rc.1 (sequence 1) and 1.0.0 (sequence 2), Authenticode-signed with release manifests;
   the agent 1.0.1 (sequence 3), whose `.wxs` gets a custom action failing right after the
   recovery actions (past `InstallServices`), built by WiX directly; the viewer 1.0.0 and 1.0.1.
   Every MSI passes Windows Installer's validation (`wix msi validate`): an ICE error fails the
   build.
6. **The upgrade candidate**: the plan built again with the helper trusting the CI test key
   alone and dialing the lab's names (`https://packages.lab.invalid/...`,
   `https://updates.lab.invalid/_lab/required-version`), then the agent packaged as the
   workspace's version, the workflow's run number as its sequence and `g<commit>` as its build
   (`0.1.0+g0123456789ab`), the token also written into `lab/build.txt`: a dev build, its
   binaries and MSI Authenticode-signed with the run's certificate (`--authenticode-only`), its
   manifest signed by the CI test key (`--ci-test-signing`; the listing says `ci_test`, so
   `seaworthy repo` refuses it). Its `lab-build.json` records the build, the SHA-256 of the key
   it trusts and the SHA-256 of every file. Runs on `main` keep it as the `lab-upgrade-windows`
   artifact (30 days): the next run's previous build.

The bundle (`windows-lab-bundle`, kept three days) holds `bin\` (the stub, the probe, the two
test executables, `seaworthy-lab`), `codesign.pem`, each release's `packages\` directory, the
upgrade candidate as `upgrade\` and a `manifest.txt` listing every file with its SHA-256.

## The lanes

Each lane is a job on a fresh runner that installs the bundle's MSIs and writes JUnit reports;
a failed lane uploads its reports and evidence.

| Job | Script | What it proves |
|---|---|---|
| `install` | `scripts/windows-msi-install.ps1` | The desktop MSI installs its launcher, cores and data files, the Start-menu and desktop shortcuts, one Programs and Features entry with its install location and the product icon Windows Installer caches; the launcher runs a core; 1.0.1 upgrades it in place; the removal leaves nothing. |
| `update` | `scripts/windows-msi-update.ps1` | See below. |
| `upgrade` | `scripts/windows-upgrade-previous.ps1`, `scripts/windows-upgrade.ps1` | The previous lab build updated to this run's by its own helper, over TLS from the lab: see below. |
| `scm` | `scripts/windows-scm-e2e.ps1 -Phase Service` | The SCM product's MSI registers the service under its virtual account with its recovery actions and DACLs; the service runs as `NT SERVICE\acme-e2e`; a fatal outcome, a panic and a crash are each restarted by the SCM after the configured delay; a version rejection (running or at connect) asks for an update and keeps the service running, and a stop during the connect wait is a clean exit; a clean stop isn't restarted; the uninstall removes the service. `tests/windows_scm.rs` (`SEAWORTHY_WINDOWS_SCM_E2E=1`, `--ignored`, one thread) runs inside it. |
| `policy-live` | `windows_policy_live` | `read_policy` and the update requester against real HKLM keys: the MSI's default, Group Policy winning, and keys others can write refused (`SEAWORTHY_WINDOWS_LIVE_REGISTRY=1`; the job fails if the test reports it skipped). |
| `fips` | the build with `-Fips`, then `windows-scm-e2e.ps1 -Phase All` | Schedule and dispatch only, informational. The cores, the stub, the probe and the SCM test on the FIPS module, `fips_selfcheck --expect-fips` natively, `verify`'s Windows FIPS checks, the module's DLL laid beside the installed cores, and the whole SCM suite with `fips=true` asserted. |

### The update lane

The agent 1.0.0-rc.1 is installed by hand; the lane's stub answers `1.0.0` and serves release
1.0.0 and its signed manifest; starting the helper's service makes the helper verify, stage and
hand the release to msiexec, and Windows Installer upgrades the product. Then a second helper
run finds nothing to do, a standard user's repair can't change the update policy, the broken
1.0.1 rolls back, the removal leaves nothing, and finally a standard user who created the
product's `%ProgramData%` directories before the install loses them to it (SYSTEM owns them
afterwards) and the helper still updates from there.

It keeps the fixes this lane was built around:

- **Ordering.** The `sequence` step reads each MSI's tables through Windows Installer:
  `RemoveExistingProducts` runs right after `InstallInitialize`, so nothing that writes to the
  script sits between them (Windows Installer fails the install with 1603 otherwise).
- **Rollback.** The custom actions that restore a removed version's recovery actions and helper
  DACL are type 3426 (rollback, in the script, no impersonation, exit ignored), scheduled in the
  removal's sequence before `DeleteServices` with the condition `Installed AND REMOVE="ALL"`;
  the rollback step then checks the recovery actions and the helper's DACL came back.
- **DACLs.** The helper service's DACL is compared with the `.wxs`'s after the install, after
  the upgrade, after the rollback and after the install over squatted directories.
- **Signing.** Every installed binary and both signed MSIs verify with Windows itself
  (`Get-AuthenticodeSignature`) against the run's `CA:FALSE` certificate, trusted for the run
  only.
- **`%ProgramData%`.** The squat step.

### The upgrade lane

The Windows side of the upgrade-from-previous lanes ([testing.md](testing.md)), with the same
rules and checks as the Linux and macOS lanes:

1. **The previous build.** `scripts/windows-upgrade-previous.ps1` (`scripts/upgrade-previous.sh`
   ported, its rules unchanged) picks the latest successful run of `lab-windows.yml` on `main`
   (a push, the schedule or a dispatch, the repository's own head, a lower run number), downloads
   its `lab-upgrade-windows` artifact with the job's token (`actions: read` only; Windows' own
   `curl.exe` reads it from a header file in a directory only the job's account can open, never
   from its command line) and checks the zip against the SHA-256 digest GitHub recorded at
   upload, then every file against `lab-build.json`, unpacking entry by entry (nothing outside
   the directory, no stream names). With nothing to update from (the lane's first run on `main`,
   an expired artifact, a build trusting a rotated test key) it exits 3 and the lane is skipped
   with a warning; any download or digest failure fails it. Its `-Phase SelfTest` runs first, in
   the job's Windows PowerShell.
2. **The lab.** `seaworthy-lab ca` makes a throwaway CA, name-constrained to
   `packages.lab.invalid` and `updates.lab.invalid`, its key never written; the lane adds it to
   `LocalMachine\Root` for the run only and maps both names to 127.0.0.1 in the hosts file.
   `seaworthy-lab serve` listens on 127.0.0.1:443 with the CA's leaf and serves the release tree;
   its required-version endpoint reads a token file on every request, which the lane switches
   from the previous build's token to the candidate's without a restart, reading each answer
   through `seaworthy-lab required-version` (the helper's own TLS construction on the machine's
   trust store).
3. **The previous build** installed by msiexec: the service runs, its helper's service waits, the
   installed-release record (`HKLM\SOFTWARE\AcmeE2E\Agent\Release`) names it; the lane writes a
   file into the service's state directory.
4. **An `off` policy honored**: Group Policy's key
   (`HKLM\SOFTWARE\Policies\AcmeE2E\Agent\UpdatePolicy`, owned by Administrators, writable only
   by SYSTEM and Administrators) says `off`; the update asked for as the service asks it
   (`StartService` on `AcmeAgent-update`) installs nothing and fetches nothing.
5. **Another key refused**: the candidate's manifest re-signed by a throwaway key
   (`seaworthy-lab foreign-manifest`); the helper fetches and refuses it ("no trusted release key
   verified it").
6. **The update**, after the helper's backoff (at least 70 s: a run within 30 s of the last is
   throttled, a failed release waits a minute): the helper verifies and stages the candidate and
   hands it to msiexec.
7. **The transition**: the record names the candidate's release, one Programs and Features entry
   (the derived UpgradeCode, deliberately not pinned, held across the two builds), the service
   runs again in a new process (another PID, started after the update was asked, the installed
   launcher, its core's start-up line), the installed files are the candidate's
   (`lab\build.txt`, every binary's version resource), the helper's service is installed and
   stopped with the DACL it had before (the candidate's `.wxs`'s), and the service's state
   survived. Then the removal leaves nothing.

The lane undoes every change in a `finally` block: the server, the CA, the hosts file (restored
byte for byte), the policy key, the product and its `%ProgramData%` directory. An always-run
step runs `windows-upgrade.ps1 -Phase Cleanup` after it, which removes whatever a run killed
before its `finally` left behind (any root named `seaworthy lab CA ...`, the hosts lines marked
`# seaworthy lab`, the product).

## The entropy probe

`entropy.first_draw_never_aborts` starts 1000 fresh `entropy_probe` processes, four at a time,
and fails if any dies on its first random draw. AWS-LC seeds its DRBG on a process's first draw;
with CPU-jitter entropy linked in (every FIPS build, and every non-FIPS Windows build unless it
opts out), that draw runs the jitter source's startup health tests and the process aborts
(`0xC0000409`, no output) when they fail. On bare metal that doesn't happen; in small virtual
machines it can.

GitHub's runners are Hyper-V guests, so the rate there belongs to the hypervisor and the host's
load, not to the change under review, and no pull request could fix it. The lab therefore runs
the probe as its own step (`-Phase Entropy`), after the SCM suite and outside its result: the
step turns orange instead of failing the job, its verdict goes to the job summary, and its
report is kept as the `windows-lab-entropy` artifact for 30 days, so the rate is measured on
every run. The FIPS lane runs it inside the suite, informational as the whole lane is. The
required lanes stay exposed only where the product is: the SCM suite's service draws no
randomness from AWS-LC, and the update lane's helper makes a few first draws per run (its
staging names), against the probe's thousand. If the rate turns out high enough to fail those,
the probe's reports say so first.

For products: a FIPS build can't opt out of jitter entropy, so a FIPS application calls
`seaworthy_crypto::module::startup_self_check()` first in `main` (an abort then happens at
boot, where the service manager restarts it, never mid-request; [fips.md](fips.md)). A non-FIPS
Windows build that must run in small virtual machines can opt out with the target-scoped
`AWS_LC_SYS_NO_JITTER_ENTROPY_x86_64_pc_windows_msvc=1` in its cargo configuration (this
repository keeps jitter: `.cargo/config.toml` names the switch).

## What CI can't show

An OS shutdown (`SERVICE_CONTROL_SHUTDOWN`) and the auto-start at the next boot need a reboot a
job can't survive; the SCM suite reports them as skipped, `EXPECTED VM-ONLY`. A domain-joined
machine is out of reach too. Both stay a physical or virtual machine check before a release.
The GitLab template's other Windows path, `seaworthy adopt-msi` (an MSI built from the `.wxs` on
a Windows runner, then signed and listed on Linux), is not part of this lab.

## Running it yourself

On a disposable Windows machine (it installs WiX machine-wide, MSIs and services, writes HKLM,
creates and removes a local user) with Visual Studio's MSVC tools, rustup and PowerShell 7, in
an elevated shell at the repository root:

```powershell
pwsh -NoProfile -File scripts\windows-lab-build.ps1 -Out C:\lab
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\windows-msi-install.ps1 -Bundle C:\lab\bundle
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\windows-msi-update.ps1 -Bundle C:\lab\bundle
powershell -NoProfile -ExecutionPolicy Bypass -File scripts\windows-scm-e2e.ps1 -Phase Service `
    -BinDir C:\lab\bundle\bin -Msi (Get-Item C:\lab\bundle\scm\packages\*.msi).FullName `
    -RustScmTestExe C:\lab\bundle\bin\windows_scm-test.exe
```

Each lane expects a machine where its product isn't installed; use a fresh one per lane, as CI
does. The upgrade lane needs a previous build: `windows-upgrade.ps1 -Previous <dir>` takes the
`upgrade-candidate` directory of an earlier build (another commit, or a lower
`-UpgradeSequence`); `windows-upgrade-previous.ps1` fetches one only inside GitHub Actions. The
pure parts run anywhere PowerShell 7 does:

```sh
pwsh -NoProfile -File scripts/windows-lab-build.ps1 -Phase SelfTest          # certificate, broken .wxs, lab-build.json
pwsh -NoProfile -File scripts/windows-scm-e2e.ps1 -Phase SelfTest            # parsers, quoting, JUnit
pwsh -NoProfile -File scripts/windows-upgrade-previous.ps1 -Phase SelfTest   # selection rules, artifact and zip checks
pwsh -NoProfile -File scripts/windows-upgrade.ps1 -Phase SelfTest            # release spellings, DACLs, hosts file
scripts/check-powershell.sh                                                  # every script, 5.1 syntax
```

## Bumping a pin

The WiX, osslsigncode, NASM and Ninja pins are parameters at the top of `scripts/windows-lab-build.ps1`
(version, URL and SHA-256 together), not managed by Dependabot. Take each digest from the
publisher (WiX's release metadata, GitHub's asset digest; for NASM, compare with an independent
record such as Scoop's manifest), download the file, and check that `Get-FileHash` agrees before
committing. WiX moves together with the CLI (`crates/seaworthy/src/wix.rs` names the version
in its errors) and `scripts/ci/seaworthy-msi.ps1`.
