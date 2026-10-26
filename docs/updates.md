# Updates

How a product shipped with seaworthy updates itself: the parts, what each one trusts, what an
administrator controls, and the signed formats. The crates are `seaworthy-updater` (the request
API, the policy readers, the helper, the installers, relaunch) and `seaworthy-formats` (the
signed contract the seaworthy CLI and the helper share).

## Architecture

```text
   app (unprivileged)                         machine (administrator)
 ┌────────────────────┐   1. asks (no data)   ┌──────────────────────────────┐
 │ UpdateRequester    │ ────────────────────▶ │ update helper (root/SYSTEM)  │
 │  reads the policy  │                       │  re-reads the policy         │
 └────────────────────┘                       │  2. version source ─────────▶│ product's server
                                              │  3. manifest ◀───────────────│ release storage / CDN
                                              │  4. package  ◀───────────────│ (untrusted)
                                              │  5. installer ──▶ apt/dnf/pacman/msiexec/installer
                                              └──────────────────────────────┘
```

### The requester

`UpdateRequester::on_version_mismatch(local, remote)` is the app's one call when its server
rejects its version. The requester knows no transport or RPC framework: the app recognizes the
rejection in its own error type and passes the two version tokens, which are only logged. The
requester reads the machine's policy and, under `auto`, asks the helper to run, at most once per
interval (5 minutes by default). Asking carries no data, so a compromised app cannot steer the
helper:

| Platform | How the app asks |
|---|---|
| Linux service | truncates `/var/lib/<state-directory>/update-request`; a systemd path unit starts `<service>-update.service` |
| Linux desktop app | `systemctl start --no-block --no-ask-password <package>-update.service`, allowed for an active local session by the package's polkit rule |
| macOS service | writes the request time to `/Library/Application Support/<Vendor>/<Directory>/state/update-request`; a LaunchDaemon watches it |
| Windows | `StartServiceW` on `<service>-update` (or `<package>-update` for a desktop app), the one right the MSI grants |

Under `notify` or `off` the requester logs the required version instead.

### Administrator policy

The policy is `auto` (install), `notify` (log the required version) or `off`. It is read by the
app before asking and again by the helper before installing; neither trusts the other's reading.

| Source, highest first | Windows | Linux, macOS |
|---|---|---|
| Group Policy / MDM | `HKLM\SOFTWARE\Policies\<Vendor>\<Directory>\UpdatePolicy` | |
| Package hold | | `apt-mark hold`, `dnf versionlock`, pacman's `IgnorePkg` (as `pacman-conf` resolves it): `off` |
| Administrator's file | | `/etc/<vendor>/<id>/policy.toml` |
| Installer default | `HKLM\SOFTWARE\<Vendor>\<Directory>\UpdatePolicy` (the MSI's `UPDATES=`) | |
| Product default | `seaworthy.toml`'s `updates.default` | the same |

Failing safe means not installing. A source a non-administrator could have written counts as
`off`, with a warning naming why: on Linux and macOS a file, or a directory above it up to
`/etc`, that isn't root's, is group- or world-writable, or is a symlink; on Windows a key, or a
key above it up to `SOFTWARE`, owned by anyone but SYSTEM, Administrators or TrustedInstaller,
without a DACL, or granting anyone else a write right. A value that doesn't parse is `off`, and
so is a missing file under a directory someone else could write (they could have removed the
administrator's file).

The Linux file accepts comments and at most one each of two settings, nothing else:

```toml
# /etc/acme/agent/policy.toml
updates = "notify"
server = "https://updates.example.com"
```

`server` (or `Server` in either Windows key) is the update server an administrator set for the
machine (`read_admin_server`): an `https://` URL with a host, an optional port and path, no user
name, query or fragment, at most 2048 bytes. An untrusted or invalid setting is an error, never a
fallback to the product's default. An app whose user points it at another server still
connects, but treats its updates as `notify` (`is_machine_server`): a per-user endpoint cannot
drive a machine-wide install.

### The helper

A per-product binary built on `seaworthy_updater::helper::main`, running as root (systemd unit
with a private `CacheDirectory=`), as a launchd daemon on macOS, or as the LocalSystem service
`<service>-update` on Windows. It takes no input from the app and runs these steps, stopping at
the first refusal:

1. re-read the policy: anything but `auto` ends the run;
2. check the staging directory and take its lock (one run at a time); sweep a previous run's
   leftovers; end the run if the last one started under 30 seconds ago;
3. ask the package manager which release is installed;
4. ask the version source for the token the server requires;
5. consult the failure memo (a failed version backs off from 1 minute, doubling to 6 hours),
   then record this attempt;
6. fetch and verify the signed manifest for that exact token;
7. apply the version floor;
8. download the package to its exact size, check its digest, its format magic and (rpm, pacman,
   with pinned keys) its own OpenPGP signature;
9. check the installed release didn't change meanwhile, install through the OS package manager,
   and confirm the new release is installed.

`helper::main` bounds a run to 1700 seconds (under the unit's `TimeoutStartSec=1800`) and exits 0
for an install, a hand-off, nothing to do, a policy that isn't `auto`, another run in progress, a
backoff or a run too soon; 1 otherwise.

### The version source

The helper learns the required version from a **caller-supplied async closure**
(`HelperConfig::new`'s `probe`), so it depends on no RPC framework. A product with a server asks
it, typically with the same version check its app's connection makes; a serverless product can
answer from a signed record of its latest release. The closure runs under a timeout
(`PROBE_TIMEOUT`, 60 seconds); its answer must pass the version-token gate
(`seaworthy_formats::validate_version`: `[A-Za-z0-9._+-]{1,128}`, no `..`), and a configured
prefix (`v`) is removed. The answer is not trusted beyond that: a signed manifest must name
exactly that token, and the version floor still applies. Build the closure from
administrator-controlled inputs only (the compiled-in default server, `read_admin_server`).

### Manifest verification

The helper derives the package URL from its template (`{product}`, `{channel}`, `{version}`,
`{target}`, `{format}`; the token's `+` sent as `%2B`) and fetches `<url>.manifest` (the query
survives byte for byte). The manifest must:

- parse strictly and re-encode to the exact same bytes;
- carry a signature line from a key compiled into the helper that verifies over the statement
  (checked first, so every later comparison runs over authenticated content);
- name the product's package and channel, the server's exact `version+build`, the helper's own
  target triple and the installer's format;
- name a size within the helper's cap (1 GiB by default).

### The version floor

A release is a version (`MAJOR.MINOR.PATCH`, optionally `-alpha`, `-beta` or `-rc` with one
number) and a sequence (the release pipeline's build number, at least 1). The helper installs
the manifest's release only when it is newer than the installed one (version first, then
sequence); the same release is nothing to do; an older one is refused unless the product opts
into downgrades (`allow_downgrades`). The installed release is read back from the package
manager only in the exact spelling the seaworthy CLI writes (a package from elsewhere is
refused, not guessed at), and every package format orders this grammar the same way.

### Staging

| Platform | Staging directory | Required |
|---|---|---|
| Linux | `/var/cache/<vendor>/<id>` (systemd's `CacheDirectory=`) | root's, mode 0700, every directory above it root's and not group- or world-writable, no symlinks |
| macOS | `/Library/Application Support/<Vendor>/<Directory>/updates` | as Linux |
| Windows | `%ProgramData%\<Vendor>\<Directory>\updates` (the known folder, not the environment) | it and each directory above it up to `%ProgramData%`: a directory, no reparse point, owned by SYSTEM, Administrators or TrustedInstaller, writable by no one else |

Files are created exclusively (0600, never through a symlink), hashed through their own open
descriptor, and renamed to the name the installer needs. Between runs the directory holds
`.lock`, `failure-memo` (`seaworthy-update-memo:1`, written atomically) and `last-run`, plus
msiexec's last log on Windows.

### Installers

| Platform | Installer | Only our package, because |
|---|---|---|
| Debian, Ubuntu | `apt-get install` of the file | the simulated plan must install exactly our package at the release's version and nothing else |
| Fedora, RHEL | `dnf upgrade` (or `downgrade`) with every repository disabled | the file's own header names our package at the release's version |
| Arch | `pacman -U` | the printed plan is exactly our package at the release's version |
| macOS | `installer -pkg` | it resolves no dependencies; the receipt must name the release afterwards |
| Windows | `msiexec /i … /qn /norestart`, detached | an MSI installs only itself; the next run reads the release back from its `Release` registry value |

On Linux each install runs in its own transient systemd unit, outside the helper's cgroup, so a
package script that restarts services cannot kill the package manager mid-transaction. The
installers never refresh indexes, upgrade the system, or install another package.

### Relaunch

A desktop app around its own update (`seaworthy_updater::relaunch`, feature `relaunch`):
`installed_release` reads the installed release; on Linux the app offers a restart once it
changes (`relaunch(current_launcher())`); on Windows, where msiexec replaces the app's files, a
watcher in the user's session (PowerShell from the system directory, Constrained-Language-safe)
waits for the MSI's `Release` value to change and starts the app again, telling it the outcome
in `SEAWORTHY_UPDATE_RESULT` (`installed` or `timeout`).

## The security boundary

The helper installs only a release the product's server named, signed by a key compiled into
the helper, naming this product, channel, exact build, target and package format, newer than the
installed release, downloaded to its exact size and digest into a root-only directory, of the
right format, and (for rpm and pacman, with pinned keys) carrying its own OpenPGP signature from
a pinned key. Every download is https-or-loopback, on `seaworthy-crypto`'s TLS policy with the
platform verifier, redirect-refusing unless the host is on an exact allowlist, and bounded in
size and time; errors never carry a URL (presigned URLs carry credentials). The machine's
administrator decides whether it runs at all.

What each party can do:

| Party | Can | Cannot |
|---|---|---|
| Release storage, CDN, network | withhold releases, slow the helper down (bounded) | serve another product's, target's, format's or build's package, an older release, or modified bytes |
| The product's server (version source) | name which signed release to install | make the helper install an unsigned, older (without opt-in) or other product's release |
| The app, a local user | ask the helper to run (rate-limited) | pass it any data, change its policy (the policy is administrator-owned), or plant files in its staging directory |
| A release-key holder | sign releases every helper trusting the key installs | bypass the policy, the floor or the format checks |

Keys are validated at intake through `seaworthy-crypto`: small-order Ed25519 points, off-curve
P-256 points, algorithms the deployment's algorithm policy doesn't admit, and ML-DSA-87 keys
under which a signature can be forged from public data are refused. FIPS 204 defines no
ML-DSA public-key validation; seaworthy's intake test refuses the known forgery classes (an
all-zero `t1`, a single non-zero coefficient, every coefficient 512, other structured keys) and
any key whose forgeability it can measure, but it is defense in depth, not a proof that a key
is sound. Compile in only keys from your own `seaworthy keygen` or HSM, or received from their
holder over an authenticated channel. The crypto policies are install-once process globals: a
helper that sets them does so first thing in `main`, before it builds a release key or makes
its first download.

## What an administrator controls

- **Whether updates install:** `auto`, `notify` or `off`, through Group Policy or an MDM
  (Windows), the MSI's `UPDATES=` property, the policy file (`/etc/<vendor>/<id>/policy.toml`),
  or a package hold.
- **Which server the helper asks:** Group Policy's or the MSI's `Server`, or `server` in the
  policy file.
- **When:** the helper runs only when asked and at most every 30 seconds; it can be stopped
  (`systemctl stop`, the service's STOP), and an install already handed to its unit runs on.
- **What the product trusts** is fixed at build time: the release keys and OpenPGP keys compiled
  into the helper, its package URL template, its redirect allowlist and size cap.

## The signed manifest

`{package url}.manifest`:

```text
seaworthy-release-manifest:1
product=10:acme-agent
channel=6:stable
version=5:1.4.0
build=6:a1b2c3
sequence=812
target=24:x86_64-unknown-linux-gnu
format=deb
size=48213504
digest=sha512:<128 lowercase hex>

signature=ml-dsa-87:<16 hex key id>:<hex signature>
signature=ed25519:<16 hex key id>:<hex signature>
```

- **The statement** is everything up to and including the line before the blank line; every
  signature covers exactly its bytes. The first line is the domain separator. Fields come in
  this order, each once; text fields are `name=<byte length>:<value>`. `channel` is always
  present (`channel=0:` for none); `build` is the version token's build metadata (`build=0:` for
  none) and `version` carries no `+`; product, channel and target are `[A-Za-z0-9._-]{1,64}`
  without `..`; `sequence` is at least 1; `format` is one of `msi`, `zip`, `deb`, `rpm`,
  `pacman`, `tar`, `pkg`; `size` is exact and non-zero; `digest` is `sha512:` or `sha256:` and
  lowercase hex of the right length. The encoding is canonical: a verifier re-encodes the parsed
  statement and requires byte equality.
- **The signature block** follows the blank line: 1 to 8 lines of
  `signature=<algorithm>:<16 lowercase hex key id>:<lowercase hex signature>`, a final newline,
  no key signing twice, nothing else. Lines naming a key the verifier doesn't trust are skipped.
  By default one trusted key verifying is enough; with `seaworthy.toml`'s
  `release-trust = "every-algorithm"`, a line must verify for every algorithm among the
  helper's trusted keys (`ReleaseTrust::EveryAlgorithm`, applied by `ManifestTrust::for_product`).
- The helper downloads exactly `size` bytes: a disagreeing `content-length` is refused before the
  body, and the stream is cut past it.

## Release keys

| Algorithm | Tag | Public key | Signature |
|---|---|---|---|
| ML-DSA-87 (FIPS 204, pure) | `ml-dsa-87` | raw, 2592 bytes | 4627 bytes |
| ECDSA P-256 / SHA-256 | `ecdsa-p256` | SPKI DER of the uncompressed point, or the raw 65-byte point (stored and identified as SPKI); compressed spellings refused | DER |
| Ed25519 | `ed25519` | raw, 32 bytes | 64 bytes |

**Key id:** the first 8 bytes of SHA-256(`seaworthy-release-key:1:<tag>:` ‖ public key bytes), a
selector, never an authenticator.

**Rotation:** ship a helper build trusting the old and the new key; sign releases with both;
once the fleet runs the two-key build, drop the old key and sign with the new one only. A
suspected leak follows the same path, removing the compromised key as fast as the fleet updates.

**Custody:** an ML-DSA-87 key is its 32-byte seed (or a PKCS#8 document); ECDSA and Ed25519 keys
are PKCS#8 documents. Keep them in a KMS, an HSM or a sealed secret store.
`seaworthy-updater`'s `examples/sign_release.rs` reads a key only from the environment and prints
one only when it generates it.
