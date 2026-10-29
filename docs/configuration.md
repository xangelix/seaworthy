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
| `fips` | no | `true`: the cores carry the AWS-LC FIPS module, and `verify` applies the FIPS binary checks (default `false`). A product's own `fips` overrides it. |
| `fips-module` | no | The `aws-lc-fips-sys` release the FIPS products' cores are built with (`"0.14.2"`), one known to build a validated or in-process AWS-LC FIPS module ([fips.md](fips.md#a-products-module-release): `0.14.2` and `0.14.3`, both AWS-LC FIPS 4.2.0); its symbol prefix and module libraries are what the FIPS checks require. Default: the release `seaworthy-crypto` pins (`0.14.3`). Set only when a product carries the module. |
| `macos-targets` | no | The macOS cores' CPU targets (default `["apple-m1"]`, which every arm64 Mac runs). |
| `macos-minimum` | no | The oldest macOS the products run on (default `"11.0"`): the deployment target and `LSMinimumSystemVersion`; `verify` refuses a binary needing a newer one. |
| `publish-sboms` | no | `true`: `seaworthy repo` publishes each installable artifact's SBOM beside it in the release tree (`<artifact>.cdx.json`). Default `false`: the SBOMs stay in `package`'s output, for you to hand out; no client fetches them ([packaging.md](packaging.md#sboms)). |

`[defaults.authenticode]` pins who may Authenticode-sign (required to sign with Authenticode). It
pins by subject and chain, not by certificate, because short-lived signing certificates change
while the identity and its CA stay:

| Key | Meaning |
|---|---|
| `subject` | The signing certificate's subject exactly as `osslsigncode verify` prints it: RFC 2253 form, the last RDN first (`O=Acme,CN=Acme Code Signing`). |
| `trust` | A PEM file of the trust anchors the signer's chain, and its timestamp's, must verify to. |

`[defaults.apple]` pins who may Developer ID-sign the macOS outputs (required to sign with
`signing.toml`'s `[apple]`). It pins the team, not the certificate: Developer ID certificates are
renewed while the team stays. A pinned team also means a release's macOS outputs are always signed:
the CI templates refuse a release whose macOS step got no `[apple]` signer.

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
trusts or signs with them: a helper trusts them only when built with
`SEAWORTHY_ALLOW_CI_TEST_KEYS=1` (`seaworthy_updater::ci_test_keys!` and
`ManifestTrust::with_ci_test_keys`), and `verify` refuses a binary carrying them, or the marker
such a build embeds, outside a `--ci-test-signing` build.

### `[product.<id>]`

The id is `[a-z0-9][a-z0-9-]*`; the Linux package name is `<vendor>-<id>`, lowercase.

| Key | Required | Meaning |
|---|---|---|
| `display-name` | yes | The name shown to people (menus, Programs and Features, the shortcuts, the macOS bundle). |
| `description` | yes | One-line package description. |
| `executable` | without `programs` | The launcher executable's file stem (`AcmeAgent`). |
| `launcher-bin` | no | The launcher's cargo binary when it isn't named as `executable` (`acme-agent-launcher`): the build plan builds `--bin <launcher-bin>` and ships it as the executable. For a workspace whose development binary already holds the executable's name (two binaries of one name in a workspace collide in its target directory). `[A-Za-z0-9][A-Za-z0-9_-]*`; never another program's, nor the helper's. |
| `aliases` | no | Other names the launcher installs under too, each a copy beside it: started by one, the program runs as ever (its cores found beside it) and reads that name as its first argument, for a program that acts by the name it was started as (an askpass helper git or ssh starts, a multi-call binary). File stems, never another name of the product's (a program's executable or alias, the helper), case-insensitively; never on `PATH`, nor started by a shortcut or the service. Stamped and signed as the launcher is. |
| `core` | without `programs` | The core cdylib's crate name (`acme_agent_core`). |
| `programs` | no | `[[product.<id>.programs]]`: several programs, each its own launcher and cores ([below](#productidprograms)). Without it, `executable`, `core`, `launcher`, `launcher-bin`, `aliases` and `linux.command` describe the product's one program. |
| `outputs` | yes | The deliverables, each once: `msi`, `zip`, `deb`, `rpm`, `pacman`, `tar`, `dmg` (a desktop app alone), `pkg` (a macOS service, a tool, or a product with `cli` programs: [packaging.md](packaging.md#macos)). |
| `kind` | no | `service` (the default; needs `[service]`), `desktop` (run by the logged-in user; its helper is started through the interactive-users grant or a polkit rule) or `tool` (no service, no helper start right). |
| `launcher` | no | The launcher crate's path from the workspace root (the directory of `build-plan --manifest`), for builds that follow the build plan. |
| `helper` | unless `updates.default = "off"` | The update helper executable's file stem, different from every program's executable. A helper needs `release-signatures` and `release-keys`. One per product, whatever its programs. |
| `helper-crate` | no | The helper's crate path from the workspace root: the build plan builds it from its own manifest, so only its own features are enabled (without it the helper is built `--bin <helper>` from the workspace root, which unifies every member's features). |
| `windows-directory` | with `msi` | The Windows install directory under the vendor's (default: the display name's last word). It also names the state directory, the policy registry key and the Group Policy namespace, so it must never follow a display-name change. |
| `conflicts` | no | What this product can't be installed beside. A product id of this `seaworthy.toml`: on every platform both build for, the Linux packages conflict (deb `Conflicts:`, rpm `Conflicts:`, pacman `conflict`),, the MSI refuses to install while the other's MSI is installed (found by its UpgradeCode, never removed), and the macOS pkg while the other's pkg is (its receipt); it holds both ways, so listing it on one product is enough. Anything else is a plain Linux package name (`[a-z0-9][a-z0-9.-]+`), which the Linux packages alone conflict with (so a Linux package must be an output); never a package this file builds (name its product) or one `linux.replaces` names. Unlike `linux.replaces`, nothing is replaced: an upgrade never swaps one product for another. Products that conflict may share a command, `windows-directory`, `desktop.app-id` and their shortcuts' name, which only one installation holds (never `macos.bundle-id`); no product conflicts with itself. |
| `fips` | no | Whether this product's cores carry the AWS-LC FIPS module (default: `defaults.fips`): `verify` applies the FIPS checks to its binaries alone, so one `seaworthy.toml` can list a product per crypto build (`trove-fips` with `fips = true`, `trove-portable` with `fips = false`), each program's `features` choosing the build. |
| `msi` | no | `[product.<id>.msi]`: who the MSI installs for, a licence page, `PATH`, Windows Error Reporting ([below](#productidmsi)). |
| `file-types` | no | `[[product.<id>.file-types]]`: the document types the `gui` program opens, registered on every platform ([below](#productidfile-types)). |
| `upgrade-code` | no | The MSI's UpgradeCode, `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`, which ties every release together. Default: derived from the vendor and the id; set it to keep an existing code before renaming either, and to the code a product's earlier MSIs carry when another tool built them ([packaging.md](packaging.md#migrating-an-existing-product)). `seaworthy check` notes an `msi` product without one. |
| `updates.default` | no | The install-time update policy: `auto` (the default), `notify` or `off`. |
| `sidecars.windows` | no | File-name globs (`*` only) matched in each Windows core build: each matches exactly one file, identical in every build, shipped beside the cores (the FIPS module's DLL). |
| `sidecars.macos` | with `fips` (the product's) and a macOS output | The same for macOS (`libaws_lc_fips_*_crypto.dylib`), shipped in `Contents/Frameworks`. |

`[[product.<id>.programs]]`: a product of several programs (a command-line tool and an app, say),
in place of `executable`, `core`, `launcher`, `launcher-bin`, `aliases` and `linux.command`, which can't be set beside it:

```toml
[[product.trove.programs]]
executable = "trove"               # /usr/bin/trove
launcher = "crates/trove/cli"
core = "trove_cli_core"
role = "cli"
features = ["fips"]
default-features = false

[[product.trove.programs]]
executable = "TroveApp"            # the menu entry, the shortcuts, the macOS app bundle
launcher = "crates/trove/app"
core = "trove_app_core"
role = "gui"
```

| Key | Default | Meaning |
|---|---|---|
| `executable` | required | The launcher's file stem. No two programs of a product share one (case-insensitively), nor with the helper. |
| `core` | required | The core cdylib's crate name. No two programs of a product share one: their cores install side by side as `<core>_<cpu>`. |
| `launcher` | — | The launcher crate's path from the workspace root, as above. |
| `launcher-bin` | the executable | The launcher's cargo binary, as above: built by that name, shipped as `executable`. No two programs of a product share one. |
| `aliases` | `[]` | Other names this program's launcher installs under too, beside it, as above. |
| `role` | required | `cli`: put on `PATH` as `command` (`/usr/bin/<command>` in the Linux packages, `/usr/local/bin/<command>` in the macOS pkg; on Windows the install directory joins `PATH` with `[product.<id>.msi] path = true`), installed on macOS in the product's tool directory. `gui`: the program `[product.<id>.desktop]`'s menu entry and shortcuts start, and the macOS app bundle's executable; at most one per product. |
| `command` | a `cli` program's executable | The name it is put on `PATH` as (`[a-z0-9][a-z0-9._+-]*`, at most 64 bytes): a `cli` program's executable must be such a name unless it sets one, and a `gui` program is put on `PATH` only when it names one. No two programs, nor two products, share one. |
| `features` | `[]` | Cargo features of the core crate this program's cores build with (`--features`): names of `[A-Za-z0-9_+.-]` or `<package>/<feature>`, each once. Only the cores: the launcher builds as its crate says. |
| `default-features` | `true` | `false` builds the cores with `--no-default-features`. |

Every program gets its own launcher and one core per CPU target (`targets`, `macos-targets`). A core
built with features of its own builds in a target directory of its own, named for the CPU and the
feature set (`<cpu>.f<8 hex>`, the hex from the feature set's SHA-256), and lands there in the
artifact directory ([packaging.md](packaging.md#the-artifact-directory)), so products building one
core crate with different features (one per crypto profile, say) never share a build, while two
building it alike build it once. A service runs the first program. The update helper stays one per
product.

The single-program keys are shorthand for one program: `executable`, `core`, `launcher`,
`launcher-bin` and `aliases` as given, with the core crate's default features; a `gui` program for `kind = "desktop"`, a `cli`
program otherwise; on `PATH` only as `linux.command`, and only on Linux, as before; on macOS in the
app bundle, as before, but for `kind = "tool"`, which has none (its program installs in the tool
directory). A `tool`
product may hold a `gui` program, and a `desktop` product `cli` programs: `kind` decides the service
and the helper's start right, a program's `role` how people reach it.

`[product.<id>.linux]`:

| Key | Meaning |
|---|---|
| `depends.deb`, `depends.rpm`, `depends.pacman` | Package dependencies per format, in each format's own syntax (deb alternatives with `\|`). |
| `needed` | Shared libraries the binaries may need beyond the base system's; every Linux format in `outputs` must then declare the packages that provide them. |
| `glibc` | The oldest glibc the Linux binaries must run on, `2.N` (default `2.34`). |
| `command` | `/usr/bin/<command>`, a link to the launcher in the Linux packages (`[a-z0-9][a-z0-9._+-]*`), in the single-program form (a `[[programs]]` entry names its own). dpkg and rpm replace an unowned file there without asking: pick a name nothing else uses. |
| `provides` | Virtual package names the Linux packages provide (deb `Provides:`, rpm `Provides:`, pacman `provides`), unversioned (`[a-z0-9][a-z0-9.-]+`): what another package can depend on whichever of several products (one per crypto build, say) is installed. Never a package this file builds. |
| `replaces` | Packages this product supersedes: the same program packaged under other names before it took `<vendor>-<id>`. Every format conflicts with and replaces them (deb `Conflicts:` and `Replaces:`, rpm `Conflicts:` and `Obsoletes:`, pacman `conflicts` and `replaces`), so an install removes them instead of failing on files both ship (a `/usr/bin` link, a menu entry). Never a package this `seaworthy.toml` builds. |

`[product.<id>.service]` (`kind = "service"` only):

| Key | Default | Meaning |
|---|---|---|
| `name` | required | The service name: the SCM name, the systemd unit's basename, the LaunchDaemon's label. |
| `account` | `virtual` | The Windows account, which decides the Linux identity too: `virtual` (`NT SERVICE\<name>` on Windows; under systemd the `sandbox` user, which it requires), `local-service`, `network-service` (each requiring a `sandbox` too), or `local-system` (LocalSystem on Windows, root under systemd, by this explicit choice). An MSI refuses `local-service` and `network-service`: every service running as them would share the MSI's grants. |
| `arguments` | `[]` | The launch arguments. |
| `restart-delays` | `["15s", "60s", "300s", "900s"]` | Restart delays (`15s`, `5m`, `1h`), the last repeating forever. |
| `reset-period` | `"24h"` | Windows: the stable uptime after which the escalation resets. |
| `state-directory` | — | systemd `StateDirectory=`, relative to `/var/lib`. Required when the helper ships: the update request file lives there. |
| `sandbox` | — | The systemd identity: `user`, optional `group` (default the user) and ambient `capabilities`. Any account but `local-system` needs one (no unit runs as root by omission); `local-system` refuses one. |
| `macos` | — | The LaunchDaemon's identity, `{ account = "root" }`: required with a `pkg` output, refused without one. Root is the only choice for now (a pkg creates no daemon account), so a product says it explicitly; its Linux `sandbox` user and Windows `account` stay as they are. |
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

`[product.<id>.desktop]` (a product with a `gui` program only: `kind = "desktop"`, or a
`[[programs]]` entry with `role = "gui"`; without it the app installs its files and nothing else):

| Key | Default | Meaning |
|---|---|---|
| `app-id` | `<vendor>-<id>`, lowercase | The menu entry's id: the `.desktop` file's and the icons' name. |
| `linux-icons` | `[]` | Square PNGs of the hicolor sizes (16, 22, 24, 32, 48, 64, 96, 128, 192, 256, 512), one per size, and at most one SVG. |
| `windows-icon` | — | An `.ico`: Programs and Features' and the shortcuts' icon. Without it the shortcuts show the launcher's own icon resource. |
| `start-menu` | `true` | A Start-menu shortcut to the `gui` program's launcher. |
| `desktop-shortcut` | `false` | A shortcut on every user's desktop. |
| `categories` | `["Utility"]` | The `.desktop` entry's `Categories`: at least one freedesktop main category. |
| `keywords` | `[]` | The `.desktop` entry's `Keywords`. |
| `mime-types` | `[]` | The `.desktop` entry's `MimeType`: the media types the app opens (`["inode/directory"]` for folders), which file managers offer it for, beside its file types' (`[[product.<id>.file-types]]`, which define their own). With any, `Exec` takes the file it's opened with after `--` (`-- %f`: one per launch, so an app that takes one path starts once per file picked, and the path is never read as an option). |
| `wm-class` | — | `StartupWMClass`: the window class (X11) or app id (Wayland) the app's windows carry. |

`[product.<id>.macos]` (required with a macOS output; `icon`, `category` and `localizations`
describe the app bundle, so a product without one, whose programs all install in its tool
directory, sets none of them):

| Key | Meaning |
|---|---|
| `bundle-id` | `CFBundleIdentifier`, reverse-DNS (`com.example.acme.viewer`), and the pkg's identifier (its receipt). Required and never derived: macOS keys an app's permissions, preferences and notarization to it, so it must never change. Unique per product (case-insensitively), even between products that conflict: one's install or uninstall would rewrite or forget the other's receipt, which the conflict check reads. |
| `icon` | The app icon (`.icns`). |
| `category` | `LSApplicationCategoryType` (`public.app-category.utilities`). |
| `localizations` | `CFBundleLocalizations`: the languages the app speaks, as language IDs (`["en", "de", "pt-BR", "zh-Hans"]`), each once. An app that carries its translations in its binary has no `.lproj` directories for macOS to find them by: without the list, the system's own text in the app (the standard menus and panels) stays English, and System Settings offers no per-app language. |
| `entitlements` | An XML property list (`.plist` or `.entitlements`, relative to `seaworthy.toml`) of the entitlements a Developer ID signature gives the main executable (and each launcher in the tool directory): the hardened runtime's exceptions the app needs (`com.apple.security.cs.allow-jit`, …). Ad hoc signatures carry none. |

`[product.<id>.msi]` (an `msi` output only):

```toml
[product.trove.msi]
install-scope = "either"        # per user by default, everyone on request
license = "packaging/license.rtf"  # a licence page to accept before installing
path = true                     # the install directory on PATH: its cli programs run by name
wer-exclude = ["TroveGui"]      # Windows Error Reporting leaves this program alone
```

| Key | Default | Meaning |
|---|---|---|
| `install-scope` | `"machine"` | Who the MSI installs for. `machine`: every user (`%ProgramFiles%`, `HKLM`), which takes administrator rights. `user`: the installing user alone (`%LocalAppData%\Programs`, `HKCU`, no administrator rights); a machine-wide install is refused. `either`: per user by default, or for every user when the person installing chooses it, on the setup dialog or with `msiexec /i <msi> ALLUSERS=1 MSIINSTALLPERUSER=""`. `user` and `either` are refused for a product with a service or the update helper, which are machine-wide by nature ([packaging.md](packaging.md#install-scope)). |
| `license` | — | An RTF file (relative to `seaworthy.toml`, inside its directory, starting `{\rtf`, at most 1 MiB): an interactive install first shows it, and installs only once the person installing accepts it. With `install-scope = "either"` the same dialog offers the scope. A quiet or basic-UI install (`msiexec /qn`, `/qb`, the update helper's) shows no dialog, as Windows Installer does: accepting the licence is then the deployer's business. |
| `path` | `false` | Append the install directory to `PATH`, the system's for a machine-wide install and the user's for a per-user one, and take it out again on removal, so the product's `cli` programs run by name (every program of the product installs in that one directory, so each runs by its executable's name). Needs a `cli` program. |
| `wer-exclude` | `[]` | Programs, by executable, that Windows Error Reporting leaves alone (no crash report, no "stopped working" dialog): a value under `ExcludedApplications`, in `HKLM` for a machine-wide install and `HKCU` for a per-user one. Windows matches the executable's file name, so the exclusion covers any program of that name. Each a program of the product, once. |

`[[product.<id>.file-types]]`: a document type the product's `gui` program opens (it needs
`[product.<id>.desktop]`, the program's menu entry), registered by each installer the product
builds ([packaging.md](packaging.md#file-types)):

```toml
[[product.trove.file-types]]
name = "Acme Trove archive"
extensions = ["trove"]
mime-type = "application/x-acme-trove"
role = "owner"                                  # the default
magic = [{ offset = 0, string = "TROVE" }]       # or { offset = 0, bytes = "89545256" }
linux-icons = ["icons/trove-doc-48.png", "icons/trove-doc.svg"]
windows-icon = "icons/trove-doc.ico"
macos-icon = "icons/trove-doc.icns"
progid = "Acme.TroveArchive"
uti = { identifier = "com.example.trove-archive", conforms-to = ["public.data", "public.archive"] }
verbs = [
    { id = "open", label = "Open", default = true, arguments = ["--", "{path}"] },
    { id = "extract", label = "Extract here", arguments = ["--extract", "--", "{path}"] },
]
```

| Key | Default | Meaning |
|---|---|---|
| `name` | required | The type's name as people see it: 1 to 128 characters, none of `$ [ ] { } % " \ ; < > &`. |
| `extensions` | required | File name extensions without the dot, `[a-z0-9][a-z0-9+_-]*`, at most 16 bytes, each claimed once in the product. Never one Windows runs or acts on (`exe`, `lnk`, `ps1`, `msi`, `url`, …). |
| `mime-type` | required | The media type, lowercase. An owner's is its own: a vendor (`vnd.`), personal (`prs.`) or unregistered (`x-`) subtype. |
| `role` | `"owner"` | `owner`: the program's own format, which it defines everywhere (the shared-mime-info definition with its magic and icons, the extension's default ProgID, content type and MIME database entry on Windows, an exported UTI and `LSHandlerRank = Owner` on macOS). `editor`, `viewer`: a type something else defines, which the program is offered for (`MimeType`, `OpenWithProgids`, an imported UTI; macOS's `Editor` at `Default`, `Viewer` at `Alternate`), never its default by itself. |
| `program` | the `gui` program | The program that opens it, by executable: only the `gui` program (the one with a menu entry and an app bundle). |
| `magic` | `[]` | An owner's shared-mime-info content matches (at most 8, any one matching): `offset` (at most 65535) and `string` (1 to 64 printable ASCII characters, no `\`) or `bytes` (1 to 64 bytes of hex). |
| `linux-icons` | — | The document icons (an owner's, required with a Linux package): square PNGs of the hicolor sizes, one per size, and at most one SVG. |
| `windows-icon` | — | The `.ico` the ProgID shows (required with an `msi` output). |
| `macos-icon` | — | The `.icns` the bundle shows for the type (required with a macOS output). |
| `progid` | — | The Windows ProgID, `Vendor.Type` or `Vendor.Type.Version` (letters and digits, at most 39 characters; required with an `msi` output). |
| `uti` | — | The macOS type: `identifier`, reverse-DNS (an owner's never `public.*` or `com.apple.*`), and `conforms-to`, at least one UTI (`public.data`). Required with a macOS output. |
| `verbs` | one, `open`, the default, `["--", "{path}"]` | What the file manager offers: `id` (`[a-z][a-z0-9-]*`), `label`, `default` (exactly one), and `arguments`, which end with `"--", "{path}"` (the file, after `--`, so it's never read as an option), every other one of `[A-Za-z0-9_.,:=+@/-]` (so nothing ever needs quoting). Every file type's default verb takes the same arguments (the menu entry has one `Exec`), and one verb id means one action across them. |

Two products of one `seaworthy.toml` may not claim one extension, media type, ProgID or UTI, unless
they conflict (`conflicts`: never installed together).

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
installer-identity = "Developer ID Installer: Acme Inc (ABCDE12345)"   # a pkg
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
| `installer-identity` | The Developer ID Installer identity, which signs a pkg (required for a pkg). |
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
