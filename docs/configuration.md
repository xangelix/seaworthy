# Configuration

The files the `seaworthy` command reads:

| File | Kept | What |
|---|---|---|
| `seaworthy.toml` | in the product's repository | the products: what to ship, for which CPUs and platforms, and whose signatures count |
| `signing.toml` | beside the CI configuration | where signatures come from (signers by command, file or environment variable; never secrets) |
| `publish.toml` | beside the CI configuration | where `publish` uploads the repositories, and the URL clients fetch them through |

All three refuse unknown keys, so a typo fails instead of silently dropping a setting. Keys are
kebab-case. Relative paths resolve against the file's own directory. `seaworthy check` loads and
validates `seaworthy.toml`, rendering every service for every platform, so a file that loads is one
every generator can package. What the tool does with these settings is in
[packaging.md](packaging.md).

## A complete example

```toml
[defaults]
vendor = "Acme"                                    # %ProgramFiles%\Acme, /opt/acme
targets = ["x86-64-v4", "x86-64-v3", "x86-64-v2"]  # most preferred first; the launcher's cpus, same order
channel = "stable"
release-signatures = ["ml-dsa-87"]
release-keys = [{ algorithm = "ml-dsa-87", public-key = "keys/release-mldsa87.pub" }]
openpgp-keys = ["keys/packages.asc"]               # rpm, pacman and the repositories
maintainer = "Acme Packaging <packages@example.com>"
license = "MIT OR Apache-2.0"
homepage = "https://example.com"

[defaults.authenticode]
subject = "O=Acme,CN=Acme Code Signing"            # as `osslsigncode verify` prints it
trust = "keys/codesign-roots.pem"                  # the anchors its chain and its timestamp's reach

[defaults.repository]
url = "https://files.example.com/packages"         # publish.toml's public-url

[product.agent]
display-name = "Acme Agent"
description = "Collects inventory for Acme."
launcher = "crates/agent/launcher"                 # crate paths, from the workspace root
executable = "AcmeAgent"                           # the launcher's file stem
core = "acme_agent_core"                           # the core cdylib's crate name
helper = "AcmeAgentUpdate"                         # the update helper's file stem
helper-crate = "crates/agent/update"
windows-directory = "Agent"                        # required with msi
outputs = ["msi", "zip", "deb", "rpm", "pacman", "tar"]
updates.default = "auto"

[product.agent.service]
name = "AcmeAgent"
account = "virtual"                                # NT SERVICE\AcmeAgent on Windows
arguments = ["service"]
restart-delays = ["15s", "60s", "300s", "900s"]
state-directory = "acme/agent"                     # /var/lib/acme/agent
sandbox = { user = "acme-agent" }                  # the systemd identity

[product.viewer]
display-name = "Acme Viewer"
description = "Views Acme reports."
launcher = "crates/viewer/launcher"
executable = "AcmeViewer"
core = "acme_viewer_core"
kind = "desktop"
windows-directory = "Viewer"
outputs = ["msi", "deb", "rpm", "tar", "dmg"]
updates.default = "off"                            # no helper, so no release manifests needed for it
linux.command = "acme-viewer"                      # /usr/bin/acme-viewer -> the launcher

[product.viewer.desktop]
linux-icons = ["icons/viewer-256.png", "icons/viewer-48.png", "icons/viewer.svg"]
windows-icon = "icons/viewer.ico"
desktop-shortcut = true
categories = ["Office", "Viewer"]
wm-class = "AcmeViewer"

[product.viewer.macos]
bundle-id = "com.example.acme.viewer"
icon = "icons/viewer.icns"
category = "public.app-category.utilities"

[[product.viewer.files]]
source = "assets"
destination = "share"
```

## `seaworthy.toml`

### `[defaults]`

| Key | Required | Meaning |
|---|---|---|
| `vendor` | yes | The vendor: the install directories' parent (`Acme` → `%ProgramFiles%\Acme`, `/opt/acme`) and the Linux package names' first part. A directory name (`[A-Za-z0-9][A-Za-z0-9._-]*`), lowercase-able to `[a-z0-9.-]` when a Linux package is an output. |
| `targets` | yes | The CPU targets, most preferred first (`x86-64-v4`, `x86-64-v3`, `x86-64-v2`, …). Each needs a core; the launcher's CPU list must name exactly these, in this order. |
| `channel` | yes | The release channel (`stable`): at most 64 characters of `[a-z0-9-]`. |
| `maintainer` | yes | deb `Maintainer:`, rpm `Packager:`. |
| `license` | yes | The license expression (rpm `License:`, deb copyright, pacman). |
| `homepage` | no | The vendor's http(s) address. |
| `release-signatures` | no | The release-manifest algorithms (`ml-dsa-87`, `ecdsa-p256`, `ed25519`), each once. Empty or left out, no manifest is signed, which only a `seaworthy.toml` whose products ship no update helper may do. |
| `release-keys` | to sign manifests | The release public keys the products' clients trust: `{ algorithm = "…", public-key = "<file>" }`, the file holding the key's hex as `seaworthy keygen --public` writes it. A manifest signer must hold one of them. Compile in only keys you generated (`seaworthy keygen`, an HSM) or received from their holder over an authenticated channel: ML-DSA-87 key validation is defense in depth ([threat model](threat-model.md)). |
| `release-trust` | no | Which signatures the update helpers require: `"any-key"` (the default: one signature by any trusted key) or `"every-algorithm"` (a verifying signature for every algorithm among the helper's trusted keys, for example ML-DSA-87 **and** Ed25519, so one weak, stolen or broken key is not enough; keys still rotate within an algorithm). `every-algorithm` needs at least two `release-signatures` algorithms; `package` signs with all of them either way. The helper reads it with `Product::from_config` and enforces it through `ManifestTrust::for_product` (`HelperConfig::new` refuses a trust that accepts any one key when it is set). |
| `openpgp-keys` | to sign packages | ASCII-armored OpenPGP public key files: every rpm and pacman signature, and every repository index signature, must verify against one of them alone. The update helper compiles the same files in. A binary or private key is refused at load. |
| `fips` | no | `true`: the cores carry the AWS-LC FIPS module, and `verify` applies the FIPS binary checks (default `false`). |
| `macos-targets` | no | The macOS cores' CPU targets (default `["apple-m1"]`, which every arm64 Mac runs). |
| `macos-minimum` | no | The oldest macOS the products run on (default `"11.0"`): the deployment target and `LSMinimumSystemVersion`; `verify` refuses a binary needing a newer one. |

`[defaults.authenticode]` pins who may Authenticode-sign (required to sign with Authenticode). It
pins by subject and chain, not by certificate, because short-lived signing certificates change
while the identity and its CA stay:

| Key | Meaning |
|---|---|
| `subject` | The signing certificate's subject exactly as `osslsigncode verify` prints it: RFC 2253 form, the last RDN first (`O=Acme,CN=Acme Code Signing`). |
| `trust` | A PEM file of the trust anchors the signer's chain, and its timestamp's, must verify to. |

`[defaults.apple]` pins who may Developer ID-sign the macOS outputs (required to sign with
`signing.toml`'s `[apple]`). It pins the team, not the certificate: Developer ID certificates are
renewed while the team stays.

| Key | Meaning |
|---|---|
| `team-id` | The Apple team identifier every Developer ID signature must carry (ten of `[A-Z0-9]`, as `codesign --display` prints `TeamIdentifier`). Each signature `package` makes is checked against Apple's Developer ID requirement for this team. |

`[defaults.repository]` (optional) is where the packages are published:

| Key | Meaning |
|---|---|
| `url` | The URL clients fetch the repositories through, `publish.toml`'s `public-url`: https (http only to a loopback address), written as a URL parser writes it, no credentials, query, fragment or trailing slash. |

With it, `package` also builds `<vendor>-repository` (it needs `openpgp-keys`, and a product that
builds a deb or an rpm), and no product may take the id `repository`.

`[defaults.ci-test-keys]` (optional) holds the public halves of the CI test keys a product's
non-release builds also trust (`seaworthy package --ci-test-signing`): `release-keys` and
`openpgp-keys`, as in `[defaults]`. None of them may be one of the real keys, and a release never
trusts or signs with them.

### `[product.<id>]`

The id is `[a-z0-9][a-z0-9-]*`; the Linux package name is `<vendor>-<id>`, lowercase.

| Key | Required | Meaning |
|---|---|---|
| `display-name` | yes | The name shown to people (menus, Programs and Features, the shortcuts, the macOS bundle). |
| `description` | yes | One-line package description. |
| `executable` | yes | The launcher executable's file stem (`AcmeAgent`). |
| `core` | yes | The core cdylib's crate name (`acme_agent_core`). |
| `outputs` | yes | The deliverables, each once: `msi`, `zip`, `deb`, `rpm`, `pacman`, `tar`, `dmg` (a desktop app), `pkg` (a macOS service). |
| `kind` | no | `service` (the default; needs `[service]`), `desktop` (run by the logged-in user; its helper is started through the interactive-users grant or a polkit rule) or `tool` (no service, no helper start right). |
| `launcher` | no | The launcher crate's path from the workspace root (the directory of `build-plan --manifest`), for builds that follow the build plan. |
| `helper` | unless `updates.default = "off"` | The update helper executable's file stem, different from `executable`. A helper needs `release-signatures` and `release-keys`. |
| `helper-crate` | no | The helper's crate path from the workspace root: the build plan builds it from its own manifest, so only its own features are enabled (without it the helper is built `--bin <helper>` from the workspace root, which unifies every member's features). |
| `windows-directory` | with `msi` | The Windows install directory under the vendor's (default: the display name's last word). It also names the state directory, the policy registry key and the Group Policy namespace, so it must never follow a display-name change. |
| `upgrade-code` | no | The MSI's UpgradeCode, `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`, which ties every release together. Default: derived from the vendor and the id; set it to keep an existing code before renaming either, and to the code a product's earlier MSIs carry when another tool built them ([packaging.md](packaging.md#migrating-an-existing-product)). `seaworthy check` notes an `msi` product without one. |
| `updates.default` | no | The install-time update policy: `auto` (the default), `notify` or `off`. |
| `sidecars.windows` | no | File-name globs (`*` only) matched in each Windows core build: each matches exactly one file, identical in every build, shipped beside the cores (the FIPS module's DLL). |
| `sidecars.macos` | with `fips` and a macOS output | The same for macOS (`libaws_lc_fips_*_crypto.dylib`), shipped in `Contents/Frameworks`. |

`[product.<id>.linux]`:

| Key | Meaning |
|---|---|
| `depends.deb`, `depends.rpm`, `depends.pacman` | Package dependencies per format, in each format's own syntax (deb alternatives with `\|`). |
| `needed` | Shared libraries the binaries may need beyond the base system's; every Linux format in `outputs` must then declare the packages that provide them. |
| `glibc` | The oldest glibc the Linux binaries must run on, `2.N` (default `2.34`). |
| `command` | `/usr/bin/<command>`, a link to the launcher in the Linux packages (`[a-z0-9][a-z0-9._+-]*`). dpkg and rpm replace an unowned file there without asking: pick a name nothing else uses. |
| `replaces` | Packages this product supersedes: the same program packaged under other names before it took `<vendor>-<id>`. Every format conflicts with and replaces them (deb `Conflicts:` and `Replaces:`, rpm `Conflicts:` and `Obsoletes:`, pacman `conflicts` and `replaces`), so an install removes them instead of failing on files both ship (a `/usr/bin` link, a menu entry). Never a package this `seaworthy.toml` builds. |

`[product.<id>.service]` (`kind = "service"` only):

| Key | Default | Meaning |
|---|---|---|
| `name` | required | The service name: the SCM name, the systemd unit's basename, the LaunchDaemon's label. |
| `account` | `virtual` | `virtual` (`NT SERVICE\<name>` on Windows; under systemd a sandbox user, or root without one), `local-service`, `network-service` or `local-system` (root under systemd). An MSI refuses `local-service` and `network-service`: every service running as them would share the MSI's grants. |
| `arguments` | `[]` | The launch arguments. |
| `restart-delays` | `["15s", "60s", "300s", "900s"]` | Restart delays (`15s`, `5m`, `1h`), the last repeating forever. |
| `reset-period` | `"24h"` | Windows: the stable uptime after which the escalation resets. |
| `state-directory` | — | systemd `StateDirectory=`, relative to `/var/lib`. Required when the helper ships: the update request file lives there. |
| `sandbox` | — | The systemd identity: `user`, optional `group` (default the user) and ambient `capabilities`. Any account but `local-system` needs one, or the Linux unit would run as root; `local-system` refuses one. A macOS service runs as root for now, so a `pkg` output refuses a sandbox. |
| `hardening` | `"default"` | systemd hardening: `"default"` (every directive on), `"none"`, or a table (below). |

`[product.<id>.service.hardening]` starts from a preset and changes single directives:

```toml
[product.agent.service.hardening]
preset = "none"                       # or "default"
no-new-privileges = true
protect-kernel-tunables = true
memory-deny-write-execute = true
restrict-address-families = true
extra-address-families = ["AF_NETLINK"]
```

The directives (each `true` or `false`): `no-new-privileges`, `protect-system-strict`,
`protect-home`, `private-tmp`, `private-devices`, `protect-kernel-tunables`,
`protect-kernel-modules`, `protect-kernel-logs`, `protect-control-groups`, `protect-clock`,
`protect-hostname`, `protect-proc`, `restrict-namespaces`, `restrict-realtime`,
`restrict-suid-sgid`, `lock-personality`, `memory-deny-write-execute`, `remove-ipc`,
`system-call-architectures-native`, `system-call-filter`, `restrict-address-families`,
`umask-0077`, `device-policy-closed`; plus `extra-address-families` (needs
`restrict-address-families`) and `read-write-paths` (needs `protect-system-strict`). A service that
must read the whole host should start from `none` and turn back on what it can keep, rather than
drop every directive. See [services.md](services.md) for what each platform's renderer writes.

`[product.<id>.desktop]` (`kind = "desktop"` only; without it a desktop product installs its files
and nothing else):

| Key | Default | Meaning |
|---|---|---|
| `app-id` | `<vendor>-<id>`, lowercase | The menu entry's id: the `.desktop` file's and the icons' name. |
| `linux-icons` | `[]` | Square PNGs of the hicolor sizes (16, 22, 24, 32, 48, 64, 96, 128, 192, 256, 512), one per size, and at most one SVG. |
| `windows-icon` | — | An `.ico`: Programs and Features' and the shortcuts' icon. Without it the shortcuts show the launcher's own icon resource. |
| `start-menu` | `true` | A Start-menu shortcut to the launcher. |
| `desktop-shortcut` | `false` | A shortcut on every user's desktop. |
| `categories` | `["Utility"]` | The `.desktop` entry's `Categories`: at least one freedesktop main category. |
| `keywords` | `[]` | The `.desktop` entry's `Keywords`. |
| `wm-class` | — | `StartupWMClass`: the window class (X11) or app id (Wayland) the app's windows carry. |

`[product.<id>.macos]` (required with a macOS output):

| Key | Meaning |
|---|---|
| `bundle-id` | `CFBundleIdentifier`, reverse-DNS (`com.example.acme.viewer`). Required and never derived: macOS keys an app's permissions, preferences and notarization to it, so it must never change. |
| `icon` | The app icon (`.icns`). |
| `category` | `LSApplicationCategoryType` (`public.app-category.utilities`). |
| `entitlements` | An XML property list (`.plist` or `.entitlements`, relative to `seaworthy.toml`) of the entitlements a Developer ID signature gives the main executable: the hardened runtime's exceptions the app needs (`com.apple.security.cs.allow-jit`, …). Ad hoc signatures carry none. |

`[[product.<id>.files]]`: a data file, or a directory with everything below it, installed under the
install root (data only: see [packaging.md](packaging.md#layout)):

| Key | Default | Meaning |
|---|---|---|
| `source` | required | The file or directory. |
| `destination` | the source's name | Where it installs, relative to the install root, `/`-separated. |
| `platforms` | every platform | `linux`, `windows`, `macos`. On macOS data files install in `Contents/Resources`. |
| `hidden` | `false` | Ship hidden files found below a directory source. Version-control directories never ship. |

### Text that reaches a package

`display-name`, `description`, `maintainer`, `license`, `homepage` and every dependency refuse `$`
and control characters: nFPM expands `$VAR` in package metadata with no escape (`Pay $5` would ship
as `Pay `, and `$CI_JOB_TOKEN` would ship the token).

## `signing.toml`

Where `package`, `adopt-msi` and `repo` get their signatures. Environment specific, never part of
`seaworthy.toml`; it names signers, never secrets (unless a local key file, kept out of the
repository). Whose signatures count is `seaworthy.toml`'s (`release-keys`, `[defaults.authenticode]`,
`openpgp-keys`), not this file's.

```toml
[[manifest]]                          # one per release-signatures algorithm
algorithm = "ml-dsa-87"
public-key = "release-mldsa87.pub"    # hex; one of seaworthy.toml's release-keys
command = ["release-signer", "sign"]  # statement on stdin, signature on stdout
output = "hex"                        # or "raw"
timeout-seconds = 120

[authenticode]                        # Windows binaries and the MSI
command = ["bash", "seaworthy/scripts/azure-sign.sh", "--endpoint", "<region>.codesigning.azure.net",
           "--account", "<signing account>", "--profile", "<certificate profile>", "{file}"]
timeout-seconds = 600

[openpgp]                             # rpm (embedded) and pacman (.sig)
secret-key-env = "ACME_PACKAGES_KEY_ASC"   # an armored, unprotected secret key in this variable
key = "<the key's 40- or 64-hex fingerprint>"

[apple]                               # macOS: Developer ID signing, then notarization
identity = "Developer ID Application: Acme Inc (ABCDE12345)"
installer-identity = "Developer ID Installer: Acme Inc (ABCDE12345)"   # a service's pkg
keychain = "/Users/runner/acme-build.keychain-db"
notary-profile = "acme-notary"
```

`[[manifest]]`, one per algorithm in `release-signatures`:

| Key | Meaning |
|---|---|
| `algorithm` | `ml-dsa-87`, `ecdsa-p256` or `ed25519`. |
| `key` | A local key file (hex, mode 0600; `seaworthy keygen` writes one). For tests and throwaway keys. |
| `key-env` | The environment variable holding the key's hex (a custody system's key, handed over for the run). |
| `command` | A signing program and its arguments: the statement on stdin, the signature on stdout. With `public-key`. |
| `public-key` | The public key file (hex), with `command`. |
| `output` | How `command` writes the signature: `hex` (the default) or `raw`. |
| `timeout-seconds` | `command`'s deadline (default 120). |

`[authenticode]`, osslsigncode with a local certificate, or a command:

| Key | Meaning |
|---|---|
| `certificate`, `key` | The PEM certificate chain (leaf first) and the PEM private key (mode 0600), for osslsigncode. |
| `timestamp-url` | An RFC 3161 timestamping service (osslsigncode). |
| `url` | The vendor's URL signed in (osslsigncode). |
| `tool` | The osslsigncode binary (default `osslsigncode`). |
| `command` | A signing command instead; `{file}` is the file to sign, `{description}` the product's name. |
| `timeout-seconds` | One signature's deadline (default 600; at most 3600). |

`[openpgp]`:

| Key | Meaning |
|---|---|
| `key` | The key's fingerprint (40 or 64 hex characters, never a user id). Required. |
| `home` | A gpg home holding, or reaching, the key. |
| `secret-key-env` | Or: the environment variable holding the armored secret key, imported into a private throwaway gpg home for the run. |
| `secret-key-file` | Or: a file holding the armored secret key. For the CI test keys only (public test keys kept in the repository), never a real key. |
| `gpg`, `rpmsign` | The binaries (default `gpg`, `rpmsign`). |
| `timeout-seconds` | One signature's deadline (default 600; at most 3600). |

`[apple]`, on a Mac (`package --platforms macos`):

| Key | Meaning |
|---|---|
| `identity` | The Developer ID Application identity in the keychain: its common name (`Developer ID Application: <name> (<team>)`) or its certificate's SHA-1 (40 hex characters). Required. |
| `installer-identity` | The Developer ID Installer identity, which signs a service's pkg (required for a pkg). |
| `keychain` | The keychain holding the identities and the notary profile (default: the user's search list). |
| `notary-profile` | The `xcrun notarytool store-credentials` profile holding the notary service's credentials (an App Store Connect API key, or an Apple ID with an app-specific password), kept in the keychain, never in a file `seaworthy` reads. Required: a Developer ID-signed download that isn't notarized is refused by Gatekeeper anyway. |
| `timeout-seconds` | How long notarization may take (default 1800; at most 3000). |

With `[apple]`, every Mach-O in the bundle and then the bundle are signed with the identity, the
hardened runtime and a secure timestamp (`macos.entitlements` on the main executable), and every
signature must satisfy Apple's Developer ID requirement for `defaults.apple.team-id`. The dmg (or
the pkg, signed by the installer identity) is then signed, notarized (`notarytool submit --wait`;
a rejection reports the service's log), its ticket stapled and validated, and Gatekeeper's
assessment (`spctl --assess`) must accept it. A signed release (`--signing`) with macOS outputs
refuses to run without `[apple]`. Dev builds (`--authenticode-only`) never use it.

Variables named by `key-env` and `secret-key-env` are taken out of the process environment before any
tool runs; a variable the command needs that's unset or empty stops the run. `repo` uses only
`[openpgp]`: its job needn't be handed the manifest key.

A CI test keys' file (`--ci-test-signing`) names only `[[manifest]]` signers with `key` and an
`[openpgp]` with `secret-key-file`, for keys `[defaults.ci-test-keys]` pins; it holds no
`[authenticode]` and takes nothing from the environment.

## `publish.toml`

Where `publish` uploads a repository. Environment specific, never part of `seaworthy.toml`. The
store's credentials come from the environment (`SEAWORTHY_S3_ACCESS_KEY_ID`,
`SEAWORTHY_S3_SECRET_ACCESS_KEY`, optionally `SEAWORTHY_S3_SESSION_TOKEN`), never from this file.

```toml
endpoint = "https://s3.example.com"                 # the S3 API (https; http only to loopback)
bucket = "files"
region = "us-east-1"                                 # the store's SigV4 region
prefix = "packages"                                  # every key under it
public-url = "https://files.example.com/packages"    # what clients fetch: checked after publishing
index-max-age-seconds = 60                           # the default
retention-days = 30                                  # the default
```

| Key | Default | Meaning |
|---|---|---|
| `endpoint` | required | The S3 API endpoint, without a path: https, or http to a loopback address. |
| `bucket` | required | The bucket. |
| `region` | required | The SigV4 region (`us-east-1`, or `auto` for stores that take it). |
| `prefix` | required | The key prefix every published file is under: `[a-z0-9._-]` segments joined by `/`, none of them a name the repository uses inside it (`apt`, `plans`, …). |
| `public-url` | — | The URL clients fetch the prefix through; every index, manifest and the plan are fetched back through it after publishing. Required, and exactly `[defaults.repository]`'s `url`, when the repository package is built. The CI template's repo job reads it from a plain `public-url = "…"` line. |
| `index-max-age-seconds` | 60 | The indexes' `Cache-Control: max-age` (1 to 3600). |
| `retention-days` | 30 | How long a file no plan references any more is kept (1 to 3650). |
