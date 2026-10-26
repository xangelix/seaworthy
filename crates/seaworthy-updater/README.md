# seaworthy-updater

*The server requires another version; that version becomes an installed package.*

Verified updates for applications shipped with seaworthy (native only). The app asks; a
privileged update helper learns the required version itself, verifies the signed release and
the package, and hands the exact file to the operating system's package manager, which installs
it and restarts the service. No app writes its own binaries.

## How it works

The app's server rejects an outdated client; the app's `UpdateRequester` asks the product's
helper to run; the helper installs the release the server names, or nothing. A product ships its
helper as a small binary built on `helper::main`, packaged by the seaworthy CLI (which renders the
helper's systemd units, launchd daemon and Windows service).

| Feature | Adds |
|---|---|
| (none) | the request API (`UpdateRequester`, `request_update`), the policy readers (`read_policy`, `read_admin_server`), the bounded process runner (`process`), the OpenPGP checks (`openpgp`) |
| `installers` | `installer`: apt, dnf and pacman (Linux), macOS's `installer`, msiexec (Windows) |
| `helper` | `helper`: the privileged helper, its download path, staging and failure memo (implies `installers`; brings reqwest, the platform TLS verifier and tokio) |
| `relaunch` | `relaunch`: a desktop app around its own update (implies `installers`) |

An app takes no feature; the helper binary takes `helper`; a desktop app that restarts itself
after an update takes `relaunch`. The manifest, release and product types are re-exported from
`seaworthy-formats`, so one crate is enough.

### The app side: `UpdateRequester`

When the server rejects this version, the app reads the machine's update policy and, under
`auto`, asks the helper to run. Asking carries nothing: the helper takes no input from the app.
The requester knows no transport: the caller recognizes the rejection in its own error type and
passes both versions.

```rust,no_run
# fn product() -> seaworthy_updater::Product { unimplemented!() }
# fn connect() -> Result<(), (String, String)> { Ok(()) }
use seaworthy_updater::{RequestOutcome, UpdateRequester};

let requester = UpdateRequester::new(product()); // at most one request per 5 minutes
// The app's connection failed because its server requires another version.
if let Err((local, remote)) = connect() {
    match requester.on_version_mismatch(&local, &remote) {
        RequestOutcome::Requested(_) => {} // the helper runs; keep retrying meanwhile
        RequestOutcome::NotAuto(_) => {}   // the required version was logged
        RequestOutcome::Throttled { .. } | RequestOutcome::Failed(..) => {}
    }
}
```

- **Linux service:** it truncates `/var/lib/<state-directory>/update-request`; the package's
  `<service>-update.path` unit starts `<service>-update.service`.
- **macOS service:** it writes the request time to
  `/Library/Application Support/<Vendor>/<Directory>/state/update-request`; the package's
  `<service>-update` LaunchDaemon watches it (`WatchPaths`).
- **Windows service:** it starts the `<service>-update` service, the one right the MSI grants
  the service's account on it.
- **Linux desktop app** (no service): it runs `systemctl start --no-block --no-ask-password
  <package>-update.service` as the logged-in user. The package's polkit rule lets an active,
  local session start exactly that unit; anything else is refused without a prompt.
- **Windows desktop app:** it starts the `<package>-update` service, which the MSI lets
  interactive users start and query, nothing more.
- Under `notify` or `off` it logs a warning naming the required version; an administrator
  installs that version from the product's repository.

### The helper: `helper::run`

A product's helper is a few lines: its names from the compiled-in `seaworthy.toml`, its release
keys, the package URL template, and its **version source**, an async closure answering the
version token the product's server requires.

```rust,no_run
# fn release_keys() -> Vec<seaworthy_updater::ReleaseKey> { unimplemented!() }
# async fn required_version() -> Result<String, std::io::Error> { Ok("1.4.0+a1b2c3".into()) }
use seaworthy_updater::helper::{HelperConfig, PackageSignatures};
use seaworthy_updater::{ManifestTrust, Product};

fn main() -> std::process::ExitCode {
    // First: the process's crypto policies, if it sets any
    // (seaworthy_crypto::fips_policy::install_policy and
    // seaworthy_crypto::tls::install_policy, before any key or TLS use),
    // and a tracing subscriber (the helper reports through `tracing`).
    // Then its names, from the seaworthy.toml it's packaged with (here,
    // this crate's fixture).
    let config = include_str!("tests/fixtures/helper-seaworthy.toml");
    let product = Product::from_config(config, "agent").expect("seaworthy.toml names the product");
    let trust = ManifestTrust::for_product(&product, release_keys()).expect("release keys");
    let config = HelperConfig::new(
        product,
        trust,
        "https://packages.example.com/{product}/{channel}/{version}/{target}/{product}.{format}",
        // Ask the product's server (the administrator's, from
        // seaworthy_updater::read_admin_server, else the default) which
        // version it requires.
        || async { required_version().await },
        PackageSignatures::ManifestOnly, // or Pinned(OpenPgpKeys) for rpm and pacman
    )
    .expect("a consistent helper configuration");
    seaworthy_updater::helper::main(config)
}
```

The template's `{version}` is the server's token with its `+` sent as `%2B` (AWS S3 decodes a
literal `+` in a path as a space; every server decodes `%2B` back to `+`). The seaworthy CLI
publishes each release exactly where this template points
(`{product}/{channel}/{version}/{target}/{product}.{format}`).

One run, in order, stopping at the first refusal:

| Step | Checks | A refusal means |
| --- | --- | --- |
| Policy | read again from the machine: anything but `auto` ends the run | nothing fetched |
| Staging | `/var/cache/<vendor>/<id>` is root's and private (0700), every directory above it root's and not writable by anyone else; a lock in it; a previous run's leftovers swept | nothing fetched |
| Interval | the last run started at least 30 s ago (`min_run_interval`) | nothing asked or fetched |
| Installed | the package manager that installed the product reports a release seaworthy spelled | nothing fetched |
| Server | the version source's token, the configured prefix (`v`) removed, the version charset | nothing fetched |
| Memo | the version didn't fail within its backoff (1 min doubling to 6 h); then this attempt is recorded | no manifest or package fetched |
| Manifest | signed by a compiled-in key, naming the package, channel, exact token, target and the installer's format | the package is never fetched |
| Floor | the manifest's release (version, then sequence) is newer than the installed one; equal is nothing to do; older is refused unless `allow_downgrades()` | the package is never fetched |
| Package | exact size, digest, format magic (`ar`/`debian-binary`, the rpm lead, zstd, MSI compound file, xar), and with `Pinned` keys its own OpenPGP signature (rpm, pacman) | the installer never sees it |
| Still installed | the package manager reports the same release as at the start | nothing installed |
| Install | the file's own version is the release's, and nothing but our package is touched; it runs in its own transient unit | nothing installed |
| Confirm | the package manager now reports the new release | the attempt stays in the memo |

The attempt is in the memo before the manifest is fetched, so a run that dies midway backs off
too, and so does a no-op. Only a confirmed install clears it. Between runs the staging directory
holds `.lock`, `failure-memo` and `last-run` (and on Windows msiexec's last log); anything else
is a previous run's leftover, removed at the start of the next. `helper::main` bounds the whole
run with `RUN_TIMEOUT` (1700 s, under the unit's `TimeoutStartSec=1800`) and exits 0 for an
install, a hand-off, nothing to do, a policy that isn't `auto`, another run, a backoff or a run
too soon; 1 otherwise.

### The update policy

`read_policy(&product)` answers `auto`, `notify` or `off` and where it came from. Windows: Group
Policy (`HKLM\SOFTWARE\Policies\<Vendor>\<Directory>`), then the MSI's default
(`HKLM\SOFTWARE\<Vendor>\<Directory>`). Linux: a package hold (`apt-mark hold`,
`dnf versionlock`, pacman's `IgnorePkg` as `pacman-conf` resolves it) is `off`; then
`/etc/<vendor>/<id>/policy.toml` (`updates = "notify"`, and optionally `server`; nothing else).
Otherwise `seaworthy.toml`'s `updates.default`. **A file or key a non-administrator could have
written, or one that doesn't parse, is `off`**, with a warning naming why; so is a missing file
under a directory someone else can write. A file the reading process can't open is
`PolicySource::Unreadable`: `UpdateRequester` then asks the helper anyway, since the helper
reads it as root and decides.

`read_admin_server(&product)` returns the update server an administrator set for the machine
(Group Policy's or the MSI's `Server`, or `server = "https://…"` in the policy file), or
`Ok(None)` (the product's default applies). A setting that can't be trusted, can't be read, or
isn't an `https://` URL with a host (no user name, query or fragment; at most 2048 bytes) is an
**error**, never a fallback. `is_machine_server` tells the app whether the server its user
connects to is the machine's; a user pointed elsewhere still connects, but the app treats its
updates as `notify`.

### Installers

| `Installer` | Installed release | Install | Only our package, at the release's version, because |
| --- | --- | --- | --- |
| `Apt` | `dpkg-query` | `apt-get install -y --no-install-recommends` (`DEBIAN_FRONTEND=noninteractive`, `NEEDRESTART_SUSPEND=1`, `--force-confold`, a 300 s lock wait; `--allow-downgrades` only for an allowed downgrade) | its plan (`apt-get install -s`) must install exactly our package at the release's version, and touch nothing else |
| `Dnf` | `rpm -q` (the epoch included, so one is refused) | `dnf upgrade -y --disablerepo=*`, or `dnf downgrade` for an allowed downgrade | no repository is enabled, the file's header (`rpm -qp`) is our package at the release's version, and each command refuses the other direction |
| `Pacman` | `pacman -Q` | `pacman -U --noconfirm` | its plan (`pacman -Up --print-format '%n %v'`) must be exactly our package at the release's version |
| `MacPkg` | `pkgutil --pkg-info <bundle id>` | `installer -pkg <file> -target /` | macOS's installer resolves no dependencies; afterwards the receipt must name the release |
| `Msi` | the MSI's `Release` registry value | `msiexec /i <file> /qn /norestart /l*v <log>`, detached (handed off) | an MSI installs only itself; the next run reads the release back |

Every program runs by absolute path in the C locale. Each Linux install runs in its own transient
unit (`systemd-run --wait --collect` as `<package>-install.service`, no time limit of its own),
outside the helper's unit, so a package script restarting services can't kill the package
manager mid-transaction. The helper never refreshes indexes, upgrades the system, or installs
another package.

On Windows the MSI replaces the helper's own binary, so the helper starts msiexec detached and
exits (`HelperOutcome::HandedOff`); the next run confirms the release. The helper runs as the
`<service>-update` service (LocalSystem) under the Service Control Manager, stages in
`%ProgramData%\<Vendor>\<Directory>\updates`, and refuses a staging directory (or any directory
above it up to `%ProgramData%`) that is a reparse point or that anyone but SYSTEM,
Administrators or TrustedInstaller owns or can write. `helper::log_file` opens its log in its
own `%ProgramData%\<Vendor>\<Directory>\update-logs` (SYSTEM and Administrators only, audited
like the staging directory; never the service's `logs`, which the service's account may
modify), without following a reparse point, and only as a regular file with one link that only
SYSTEM, Administrators or TrustedInstaller own and can write.

## The rules

1. **Nothing installs that the server didn't name and a pinned key didn't sign.** The manifest
   for the server's exact token is verified against the keys compiled into the helper, and must
   name the product's package, channel, `version+build`, this target and the installer's format,
   all before any package byte is fetched.
2. **Never older, never twice.** The version floor installs only a newer release (version, then
   sequence); the same release is nothing to do; an older one only with `allow_downgrades()`.
3. **The administrator decides.** The policy is read on both sides; a source a
   non-administrator could have written is `off`; holds count. The ownership checks of the
   policy sources, the staging directory and the helper's log are `seaworthy-fsguard`'s.
4. **The bytes are checked before the package manager sees them.** Exact size, digest, format
   magic and, with `Pinned` keys, the package's own OpenPGP signature; the file sits in a
   root-only directory from download to install.
5. **Only our package, through the OS installer.** No index refresh, no system upgrade, no other
   package.
6. **A failing release backs off.** The memo records each attempt before anything is fetched;
   runs are at least 30 s apart; one run at a time.
7. **Every download is bounded and TLS-enforced.** https-or-loopback only, on
   `seaworthy-crypto`'s TLS policy with the platform verifier; redirects refused unless the host
   is on an exact allowlist; size and time caps; errors never carry the URL.

## Signing a release by hand

`examples/sign_release.rs` (product packages get their manifests from the seaworthy CLI):

```sh
# once: mint a key (the only secret-printing mode; secret to stderr)
cargo run -p seaworthy-updater --example sign_release -- --generate-key mldsa87
# per package: writes {package}.manifest
SEAWORTHY_RELEASE_KEY_HEX=<hex> cargo run -p seaworthy-updater --example sign_release -- \
  mldsa87 dist/acme-agent_1.1.0-2_amd64.deb --product acme-agent --channel stable \
  --version 1.1.0+a1b2c3 --sequence 2 --target x86_64-unknown-linux-gnu --format deb
# rotation: add the second key's signature to the same manifest
SEAWORTHY_RELEASE_KEY_HEX=<new hex> cargo run -p seaworthy-updater --example sign_release -- \
  ed25519 dist/acme-agent_1.1.0-2_amd64.deb --product acme-agent --channel stable \
  --version 1.1.0+a1b2c3 --sequence 2 --target x86_64-unknown-linux-gnu --format deb --append
```

The manifest and release-key formats are `seaworthy-formats`'; see its README and
[docs/updates.md](https://github.com/xangelix/seaworthy/blob/main/docs/updates.md).

> **Warning:** path-signing presigned URL schemes (SigV4, GCS V4, Azure SAS) do not survive the
> `.manifest` path change: the fetch fails closed. Serve manifests at unsigned paths (they are
> public and self-authenticating), or use a redirect flow with the redirect host allowlisted.

## Deliberately out of scope

- **Self-replacement.** Only the OS installer writes installed files.
- **Crash-loop rollback.** Revert a bad release by shipping a newer version with the old code.
- **Staged or canary rollout.** The control point is the release pipeline and the server.

## Platform notes

Native only. The helper runs on Linux (apt, dnf, pacman, under systemd), macOS
(`installer -pkg`, under launchd) and Windows (msiexec, under the Service Control Manager).

## License

Licensed under either of Apache License, Version 2.0 or MIT license at your option.
