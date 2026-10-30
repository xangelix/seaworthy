# Packaging

How the `seaworthy` command turns built artifacts into verified install trees, signed packages,
repositories and a publication. The tool never compiles: a build (the GitLab templates, or your own
CI following `seaworthy build-plan`) leaves the binaries in an artifact directory, and every step
below reads from there. The configuration it reads is described in
[configuration.md](configuration.md); the CI templates in [ci-gitlab.md](ci-gitlab.md).

```text
artifacts ──▶ verify ──▶ layout ──▶ package ──▶ repo ──▶ publish
                │           │          │          │         │
           every finding  install   packages,   APT, DNF,  S3-compatible
           at once        trees     manifests,  pacman,    store, checked
                          (stripped) SBOMs      release    through the
                                                tree, plan public URL
```

## The artifact directory

```text
<artifacts>/<triple>/launcher/<executable>[.exe]     each program's
<artifacts>/<triple>/helper/<helper>[.exe]           when the update helper ships
<artifacts>/<triple>/cores/<build>/lib<core>.so      Linux (x86_64-unknown-linux-gnu)
<artifacts>/<triple>/cores/<build>/<core>.dll        Windows (x86_64-pc-windows-msvc), with the sidecars
<artifacts>/<triple>/cores/<build>/lib<core>.dylib   macOS (aarch64-apple-darwin)
```

`<build>` is the CPU target, or `<cpu>.f<8 hex>` for a program whose core builds with cargo features
of its own (`features`, `default-features = false`; the hex is from the feature set's SHA-256), so
two products building one core crate with different features keep apart.

Linux binaries keep their symbol tables (`strip = false`): `verify` reads them, and `layout` strips
the shipped copies. A macOS core of a FIPS product keeps its table for the same check; `layout`
strips no Mach-O. `seaworthy build-plan --triple <triple>` prints the build that fills this layout:
each program's launcher (its `launcher-bin`, copied to `launcher/<executable>`) and the helper
once (in the target directory `base`), each program's core
once per CPU target with its features, in its build's own target directory (`<build>` above), the
per-CPU flags as `target.<triple>.rustflags`. It refuses a product whose cargo configuration sets
`build.rustflags`, which cargo would ignore once target flags are set.

### Extra build flags

A product's own flags belong in `.cargo/config.toml`'s `target.<triple>.rustflags` (or
`target.'cfg(…)'.rustflags`), which cargo joins to the per-CPU flags. Flags that only a release
build should get, or that name files of the build machine, come from the environment of the CI's
build step instead (`scripts/ci/seaworthy.sh build`, `seaworthy-build.ps1`, and the GitHub workflow's
`rustflags` and `core-rustflags` inputs):

| Variable | Builds | Example |
|---|---|---|
| `SEAWORTHY_RUSTFLAGS` | every build: the launcher, the helper and each core | `--cfg release_build` |
| `SEAWORTHY_CORE_RUSTFLAGS` | the cores alone (each step whose target directory isn't `base`) | `-Cprofile-use={workspace}/pgo/{triple}.profdata` |

Each is split on whitespace, and its words follow the plan's flags in that build's
`target.<triple>.rustflags` (every build's, then the cores'). Three placeholders expand:
`{workspace}`, the workspace manifest's directory as an absolute path (cargo runs each
dependency's `rustc` in that dependency's own directory, so a relative path would name a different
file for each crate); `{triple}`, the target triple; and `{cpu}`, the step's target directory: the
core's build (its CPU, or `<cpu>.f<8 hex>` for a core with features of its own), or `base`. A flag that chooses the CPU or its features (`target-cpu`, `target-feature`)
is refused: the plan sets them per core, and each core's requirement record must name exactly what
it was built for. So is a quote (the flags travel as TOML strings) and any other `{placeholder}`.

Any other environment a build needs (a C compiler's flags, a cargo `[env]` value) is the build job's
own environment, which every `cargo` call inherits.

**Profile-guided optimization**: build an instrumented core, run it on representative work, merge
the profiles with `llvm-profdata merge` (from the `llvm-tools` component of the same toolchain),
commit the result, and pass it to every core. A profile collected on one CPU target serves the
others (LLVM matches functions by their control flow; a mismatch is a warning, not an error):

```sh
SEAWORTHY_CORE_RUSTFLAGS='-Cprofile-use={workspace}/pgo/{triple}.profdata'
```

### Source paths

rustc writes source paths into every binary: each panic location, `file!()`, the debug info. Built
as they are found, those name the build machine (`/home/<user>/…`, `/builds/<group>/<project>/…`) and
every git dependency's repository, which for a private dependency is an internal name anyone can
read with `strings`. So the build step remaps them (`--remap-path-prefix`, after the plan's flags and
before the caller's, whose own remaps then win):

| Path | Becomes |
|---|---|
| the workspace (the workspace manifest's directory) | `/workspace` |
| the target root (`SEAWORTHY_TARGET_DIR`; a build script's generated code) | `/target` |
| the toolchain's sources (`<sysroot>/lib/rustlib/src/rust`, which a toolchain with the `rust-src` component puts in the standard library's code compiled into the product) | `/rustc/<commit>`, rustc's own name for them |
| each cargo home `cargo metadata` names (the registry's sources) | `/cargo` |
| each git dependency's checkout (`<cargo home>/git/checkouts/<repository>-<hash>`) | `/cargo/git/checkouts/<hash>` |

The cargo homes and checkouts come from `cargo metadata` for the build's target, with the parts
of `SEAWORTHY_CARGO_ARGS` that say where the sources are and which features build (`--offline`,
`--frozen`, `--config`, `-Z`, the feature flags), so it resolves what the builds do and reads only
the sources they read: a vendored or offline build needs nothing more. Builds of one commit get the
same flags; they change only when a git dependency's URL does (which rebuilds everything, as any
flag change does). A panic then reads
`/cargo/registry/src/index.crates.io-…/tokio-1.54.1/src/…` or `crates/agent/src/main.rs` (cargo hands
rustc the workspace's own crates as relative paths), and a binary no longer depends on the directory
it was built in.

What stays: each crate's own directory (`<crate>-<version>`), so the dependency list can still be
read from a binary; no stable compiler option drops it (cargo's `trim-paths` and
`-Zlocation-detail=none` are nightly). Paths a crate builds itself (`env!("CARGO_MANIFEST_DIR")`),
and a path dependency or vendored directory outside the workspace, aren't remapped: give it its own
`--remap-path-prefix=<path>=<name>` in `SEAWORTHY_RUSTFLAGS`. `SEAWORTHY_REMAP_PATHS=0` (the GitHub
workflow's `remap-paths: false`) turns remapping off.

## Verify

`seaworthy verify` runs every check and reports every finding together, so one run names everything
wrong:

1. **Presence and kind.** Each program's launcher and one core per CPU target, and the helper
   (when shipped), on every platform the outputs need; each a regular file of the platform's format: ELF64 x86-64
   executables and shared libraries on Linux, PE32+ AMD64 executables and DLLs on Windows, thin
   arm64 Mach-O executables and dylibs on macOS.
2. **Core records.** Each core's `.cpureq` parses, names this platform's triple and this
   directory's CPU, and lists only feature names `seaworthy-levels` knows.
3. **Each launcher's `.cpulist`** names its program's core and exactly the configured targets, in
   order.
4. **Sidecars.** Each Windows (or macOS) sidecar glob matches exactly one file in every core build
   of every program, and the copies are byte-identical: a difference means an accidental
   per-target FIPS build.
5. **FIPS** (the product's `fips`, else `defaults.fips`). Every Linux core passes the static-link
   checks of `scripts/verify-fips-binary.sh` over its symbol table: the pinned module present, no
   second libcrypto, no other module version. On Windows and macOS every core loads the pinned
   module's library, and the sidecars ship it. A macOS core's symbol table shows the same from the
   other side: the module's symbols imported and none defined, no second AWS-LC, no other module
   version ([fips.md](fips.md#macos-cores)). The pinned module is `defaults.fips-module`'s release,
   else `seaworthy-crypto`'s ([fips.md](fips.md#a-products-module-release)).
6. **Runtime dependencies.** Windows binaries link the C runtime statically. Linux binaries need
   only the base system's libraries plus those the product declares in `linux.needed`, and no glibc
   newer than the floor (`linux.glibc`, default 2.34): every entry of the version-needs table counts,
   as glibc's loader reads it, a weakly referenced symbol's version included. A Linux core with
   initial-exec TLS (`DF_STATIC_TLS`) is refused: the launcher loads cores with `dlopen`, and glibc
   then has only a small static TLS surplus to give. macOS binaries link the system's libraries
   alone and need no macOS newer than `defaults.macos-minimum`.

An import table, dynamic section or version table that doesn't parse, a stripped Linux binary and a
stripped macOS core of a FIPS product are findings, never a pass: the checks would otherwise pass
vacuously. `verify` also warns about a
core no CPU would ever choose (its features include every feature of a more preferred core).

`seaworthy fips-check [--module VERSION] FILE…` and `seaworthy glibc-check [--floor X.Y] FILE…`
apply the FIPS and glibc rules to single files, for binaries built outside a product (a separate
FIPS builder, for example).

**Building for the glibc floor.** A build on a current distribution picks up symbol versions the
package's `glibc` dependency says nothing about (glibc 2.38's `__isoc23_*`, std's weakly referenced
`pidfd_spawnp` at 2.39): the package installs on the oldest supported system and then fails to
start. Build release binaries on a system whose glibc is at or below the floor (the GitLab template's
default build image is Debian 12, glibc 2.36, whose builds need nothing past 2.34 except libm's
`hypot` and `hypotf`, which `seaworthy_launcher::glibc_floor!` binds to the baseline), or raise the
floor and the packages' dependency together.

## Layout

`seaworthy layout` stages each platform's install tree from verified artifacts, under
`<out>/<product>/<triple>/tree/`, exactly as it installs:

| | Linux | Windows | macOS |
|---|---|---|---|
| Root | `/opt/<vendor>/<product>` (lowercase) | `%ProgramFiles%\<Vendor>\<Directory>` | `/Applications/<Display Name>.app` (the bundle); `/usr/local/<vendor>/<product>` (lowercase: the tool directory) |
| Launchers (each program's) | `<executable>` | `<executable>.exe` | the bundle's `Contents/MacOS/<executable>`; the tool directory's `bin/<executable>` |
| Aliases (`aliases`: each a copy of its program's launcher) | `<alias>` | `<alias>.exe` | beside its launcher (signed before the bundle, with its entitlements) |
| Cores (each program's) | `lib/lib<core>_<cpu>.so` | `<core>_<cpu>.dll` | beside the launcher's directory: `Contents/Frameworks/lib<core>_<cpu>.dylib`, `Frameworks/lib<core>_<cpu>.dylib` |
| Sidecars | — | beside the cores, one copy | beside the cores, one copy per directory |
| Helper | `libexec/<vendor>-<product>-update` | `<helper>.exe` | the bundle's `Contents/MacOS`, else the tool directory's `bin` (not in a dmg) |
| Data files | `<destination>`, mode 0644 | `<destination>` | `Contents/Resources/<destination>`, and `Resources/<destination>` in the tool directory |

On macOS the app bundle holds the bundled program: the `gui` program, or the single-program form's
service or desktop app. The tool directory holds every other program (`cli` programs, a tool's),
laid out like a bundle's `Contents` (`bin` for `MacOS`), so a launcher finds its cores in
`../Frameworks`, and data files in `../Resources`, wherever it is; a product may have both. The
macOS tree stages the bundle as `tree/<Display Name>.app` and the tool directory at its install
path under `tree/`.

Linux binaries are stripped (`strip --strip-all`, `$STRIP` overrides the tool) and each stripped
core's record is read back, so stripping can never cost a core its `.cpureq`; each stripped copy is
then compared with the verified one ([What changes after the build](#what-changes-after-the-build)).
`layout.json` beside each tree lists every file with its install path, role, mode and SHA-256, and
the checked steps that changed it after the build. A staging directory is replaced only if it
carries `layout`'s marker file, and a file that changed since `verify` read it is refused.

**Data files are data.** `[[product.<id>.files]]` are read once from `seaworthy.toml`'s directory,
without following links, and `layout` refuses links and special files, anything resolving outside
that directory, names Windows or the package tools refuse, native binary images (ELF, PE, Mach-O,
Java class files), on Windows anything Windows would run or act on (scripts, shortcuts, installers,
`.reg`, `desktop.ini`, a manifest beside a binary), hidden files below a directory source unless the
entry sets `hidden = true`, and version-control directories always. Code ships as the launcher, a
core, a sidecar or the helper: the files `verify` checks.

### What changes after the build

Three steps change a binary after `verify` read it, each in one known way, and each result is
compared with its input: anything else that changed in what the loader maps fails the step, naming
the file and the section or header field. A product whose cores carry a FIPS module can rely on
it: no step after the build touches the bytes the module's integrity test covers (or any other
loaded byte).

| Step | Changes | Must stay the same | `layout.json` |
|---|---|---|---|
| `layout` strips a Linux launcher, core or helper | sections the loader doesn't map (symbols, debug information) go; the section header table is rewritten (and may be reordered) | the ELF header but the section header table's offset, count and name index; every program header; every byte a `PT_LOAD` maps from the file; every allocated section a `PT_LOAD` maps: name, type, flags, address, size, file offset, contents | `"strip": "non-alloc"` |
| `package` stamps a Windows launcher, core or helper's version resource | a resource section is appended after every other section (initialized read-only data holding the new resource tree), or the image's trailing resource section (the last one, neither code nor writable, holding the resource directory and nothing another data directory points at) is rewritten in place; the section count, `SizeOfInitializedData`, `SizeOfImage`, the checksum and the resource data directory | every other section's header and file data; every other header byte the loader maps (the entry point, the image base, `DllCharacteristics`, every other data directory, …) | `"stamp": "resource-section"` |
| `package` Authenticode-signs a Windows binary (a sidecar too, the FIPS DLLs included) | a certificate table appended past every section's data; the checksum and the certificate table's data directory | every section's header and file data; every other header byte | `"sign": "certificate-table"` |

The checks read both images with their own bounded parsers, independent of the stamp's, and
treat them as untrusted input (fuzzed: `dist_post_link`). The version stamp runs its check before
it returns (`pe_version::stamp_version`); `seaworthy::post_link` holds all three for a pipeline
that strips or signs on its own. A sidecar that arrives already signed by the product's pinned
identity isn't signed again, so it carries no `sign`.

## Package

`seaworthy package` runs `verify` and `layout`, then builds every output `seaworthy.toml` names,
under `<out>/<product>/`:

| Path | What |
|---|---|
| `packages/<package>_<deb version>_amd64.deb` | Debian package |
| `packages/<package>-<version>-<release>.x86_64.rpm` | RPM package |
| `packages/<package>-<pkgver>-<pkgrel>-x86_64.pkg.tar.zst` | Arch Linux package |
| `packages/<stem>-linux-x86_64.tar.zst` | the Linux tree under one `<stem>/` directory |
| `packages/<stem>-windows-x86_64.zip` | the Windows tree under one `<stem>/` directory |
| `packages/<stem>-windows-x86_64.wxs` (and `.msi` with `SEAWORTHY_WIX`) | the MSI's source, and the MSI |
| `packages/<stem>-policy-templates.zip` | the Group Policy templates: `<Vendor>.<Directory>.admx` and `en-US/….adml` |
| `packages/<stem>-macos-arm64.dmg` | a desktop app's bundle in a disk image |
| `packages/<stem>-macos-arm64.pkg` | a service's, a tool's or a product with `cli` programs' bundle, tool directory, `PATH` links and LaunchDaemons |
| `packages/<artifact>.manifest` | with `--signing`: the artifact's signed release manifest |
| `packages/<pacman package>.sig` | with OpenPGP signing: the detached signature pacman checks |
| `packages/<artifact>.cdx.json` | the artifact's SBOM |
| `packages.json` | every artifact with its kind and SHA-256, and how it was signed |

`<package>` is `<vendor>-<product>` in lowercase; `<stem>` is `<package>-<version>-<sequence>`.

### Linux packages

nFPM 2.47.0 (`$NFPM`; `scripts/ci/install-nfpm.sh` installs the pinned release, verified by SHA-256)
builds the deb, rpm and pacman packages from the Linux tree. A service's packages carry its systemd
unit, a `sysusers.d` entry for its sandbox user, a vendor preset and, with the update helper, the
helper's path and service units. A product with a `gui` program carries its menu entry (starting
that program) and hicolor icons, and every product a `/usr/bin/<command>` link to each program put
on `PATH`; a desktop product with the helper carries the helper's unit and a polkit rule letting an
active local session start exactly that unit ([updates.md](updates.md)). The products and packages
a product conflicts with (`conflicts`) are every format's conflicts, `linux.provides` its
provides, and `linux.recommends` and `linux.suggests` deb's and rpm's weak dependencies; neither replaces anything, so a package manager never swaps one product for another (one
per crypto build: installing another profile means removing the installed one first).

One package-script lifecycle, spelled for each format:

- a fresh install creates the sandbox user, applies the host's systemd preset policy to the service
  and the update path unit through the vendor preset file, and starts what the policy enabled;
- an upgrade `try-restart`s the service and applies presets only to units new in that version; the
  update units are never restarted, because the helper may be running the upgrade;
- removal stops and disables; state and the sandbox user stay.

A masked unit is never touched, and a site preset that sorts before the vendor's keeps a unit off.
Without a running systemd (an image build) units are enabled but not started; a failed `systemctl`
call warns and the transaction goes on; deb honours `policy-rc.d` and `DPKG_ROOT`.

### Windows

Each Windows binary (the launcher, every core, the helper; never a sidecar) gets a version resource
stamped after linking, then every Windows binary is Authenticode-signed, then the zip and the MSI's
`.wxs` are written over the signed tree. The MSI:

- installs to a fixed `%ProgramFiles%\<Vendor>\<Directory>` (no command-line relocation), or
  `%LocalAppData%\Programs\<Vendor>\<Directory>` per user ([Install scope](#install-scope));
- applies the service renderers' DACLs with `MsiLockPermissionsEx`, registers the service and the
  update helper with `ServiceInstall`, and grants the service's account only the right to start the
  helper (a desktop product grants that to interactive users);
- leaves its `%ProgramData%` directories to the installed launcher, run as SYSTEM after
  `InstallFiles` on a first install or an upgrade (a deferred, no-impersonate custom action;
  never in a repair): `%ProgramData%\<Vendor>\<Directory>` and its `state` and `logs` (the
  service's account may modify them) and `updates` and `update-logs` (the helper's staging and
  log, SYSTEM and Administrators only). Windows Installer's `CreateFolder` works by path and
  follows a junction a user put in a folder's place, and a lock on a folder doesn't reach a child
  with its own protected DACL, so the launcher's guard makes each folder with its descriptor or
  takes an existing one back on a handle (never through a reparse point), audits everything below
  the product's directory, and **refuses the install** when anything there is a reparse point or
  was owned or could be written by anyone but SYSTEM, Administrators, TrustedInstaller or the
  service's account (a local user who created and filled the folders before the install; the
  Application event log names the object). The folders stay on removal, so the state survives an
  upgrade; one deleted by hand comes back with the next upgrade, not with a repair;
- runs the system's `sc.exe` for the recovery settings, on a first install or an upgrade, never in a
  repair a standard user can start (`MsiServiceConfigFailureActions` is documented as broken);
- writes the installed release (in deb's spelling) and, with `UPDATES=` and `SERVER=`, the update
  policy default and the machine's update server under `HKLM\SOFTWARE\<Vendor>\<Directory>`;
- refuses a first install while a product it conflicts with (`conflicts`, either way) is installed
  by its MSI: a detect-only search for that product's UpgradeCode (`FindRelatedProducts`, never
  removing it) and a launch condition naming it. A repair or a removal is never refused;
- with `[product.<id>.msi] path = true`, appends the install directory to `PATH` (the system's,
  or the user's for a per-user install) and takes it out again on removal; with `wer-exclude`,
  writes each named program's Windows Error Reporting exclusion
  (`…\Windows Error Reporting\ExcludedApplications`, a DWORD 1 named for the executable, as
  `WerAddExcludedApplication` writes it) under `HKLM`, or `HKCU` per user;
- allows two builds of one version (the sequence orders them) and refuses downgrades. Its
  UpgradeCode is `upgrade-code`, else derived from the vendor and the product id: pin it before
  renaming either, and to the code earlier MSIs carry when another tool built them
  ([Migrating an existing product](#migrating-an-existing-product)).

#### Install scope

`[product.<id>.msi] install-scope` chooses who an MSI installs for:

| Scope | Package | A plain `msiexec /i` | Files | Registry (`HKMU`, `HKCR`), shortcuts |
|---|---|---|---|---|
| `machine` (default) | `ALLUSERS=1` (WiX `perMachine`) | every user; needs administrator rights | `%ProgramFiles%\<Vendor>\<Directory>` | `HKLM`, `HKLM\Software\Classes`; all users' Start menu and desktop |
| `user` | Windows Installer 5's dual-purpose package, `ALLUSERS=2` and `MSIINSTALLPERUSER=1` (WiX `perUserOrMachine`), and a launch condition refusing a machine-wide install | the installing user; no administrator rights, no UAC prompt | `%LocalAppData%\Programs\<Vendor>\<Directory>` | `HKCU`, `HKCU\Software\Classes`; the user's Start menu and desktop |
| `either` | the same dual-purpose package | the installing user, as `user`; `ALLUSERS=1 MSIINSTALLPERUSER=""` installs for every user, as `machine` (a UAC prompt) | either | either |

With `install-scope = "either"`, or a `license`, an interactive install shows seaworthy's setup
dialogs ([Setup dialogs](#setup-dialogs)): `either` offers "just for me" (the default) or "everyone on
this computer" there, which sets `ALLUSERS=2` and `MSIINSTALLPERUSER` (1, or empty) as Microsoft's
single-package authoring describes, and preselects "everyone" when the command line asked for it.

A per-user install is Windows Installer's own: with `ALLUSERS=2` and `MSIINSTALLPERUSER=1` it
redirects `ProgramFiles64Folder` to the user's Programs folder, writes `HKMU` and `HKCR` rows under
`HKCU`, puts the shortcuts in the user's folders, and resets `ALLUSERS` to empty (to 1 for a
machine-wide install), which the components that differ by scope (`PATH`) are conditioned on. The
package is otherwise the same: no component, key path or custom action changes, and adopt-msi checks
it the same way. WiX's own `perUser` isn't used: it sets no `ALLUSERS`, so Program Files would stay
the machine's.

A per-user scope is refused for anything only a machine-wide install can do, so a per-user package
holds nothing that needs administrator rights (Microsoft's single-package authoring rules): a
service (registered with the service control manager, with its directories' descriptors and its
recovery actions run as LocalSystem) and the update helper (a LocalSystem service, its
`%ProgramData%` folders made by a custom action running as SYSTEM, and the update policy under
`HKLM`). A per-user product therefore updates through a new MSI, not the helper.

Windows Installer upgrades a product in the context it was installed in: install a new release of an
`either` product the way the installed one was installed (`ALLUSERS=1 MSIINSTALLPERUSER=""` again for
a machine-wide one), or the new one installs beside it. A conflict's detect-only search
(`conflicts`) is Windows Installer's same related-product search, so don't rely on it to see a
conflicting product installed in the other context.

#### Setup dialogs

A product with `[product.<id>.msi] license`, or `install-scope = "either"`, gets a full-UI setup:
a first dialog with the licence (an accept check box enabling Install) and/or the scope choice, a
progress dialog, a cancel confirmation, and Windows Installer's standard dialogs (errors, files in
use, and the finished, cancelled and failed dialogs, in the install and the administrative UI
sequences, as ICE20 requires). A quiet or basic-UI install shows none of them. Without either option
the MSI has no dialogs at all.

They are seaworthy's own, written into the `.wxs`, not WiX's WixUI sets: WixUI_Minimal's licence page
has a Print button that runs a native DLL from the `Binary` table (`WixUIPrintEula`), and
WixUI_Advanced adds a folder browser (`SetTargetPath`, so a person could install the product anywhere)
and another DLL action (`WixUIValidatePath`); both need the UI extension downloaded into the build.
seaworthy's dialogs are text only and run no code: every event ends a dialog, opens one, or sets the
scope's two properties. Their appearance is plain (no banner bitmaps) and their text English.

adopt-msi models them exactly (below), so a built MSI's dialogs can't do more than the `.wxs`
declares, and the `.wxs` itself is refused if a dialog would do more than that.

With `SEAWORTHY_WIX` naming WiX v5.0.2, `package` builds the MSI itself. Otherwise a Windows runner
builds it from the `.wxs` (`wix build -arch x64 -bindpath tree=<tree> -o <name>.msi <name>.wxs`, then
`wix msi validate`), and **`seaworthy adopt-msi`** takes it back: the MSI must carry exactly the
signed Windows tree, byte for byte, at the release's ProductVersion and the product's UpgradeCode,
and its security-relevant tables must be exactly what the `.wxs` declares (read with msitools'
`msiinfo export -s`, compared by what each row resolves to, never by the ids a tool chose):

- every custom action (its type, source and command line), service (name, account, start type,
  type, error control, arguments and the binary it runs), service control, registry value (the file
  types' `HKCR` values among them),
  `MsiLockPermissionsEx` descriptor (the directory or service it's on, and its SDDL), shortcut
  (folder, name, target, arguments, working directory) and environment change (`PATH` alone,
  appended, removed on uninstall, the system's or the user's, the directory it adds and its
  component's condition): no row more, none less, none other;
- every `Property` row: the `.wxs`'s values (the product's name, manufacturer, version, language and
  UpgradeCode, its scope's `ALLUSERS` and `MSIINSTALLPERUSER`, every `<Property Value=>`), WiX's
  ProductCode, and `SecureCustomProperties` naming only properties the `.wxs` marks secure, so no
  property the install would act on (an update server, a scope) is planted;
- the setup dialogs' tables, row for row, by every column that decides what a dialog does: each
  dialog, each control's type and the property it's bound to, each control event (event, argument,
  condition, order), control condition, event subscription, radio button and check box value, text
  style, and where the sequences show each dialog; a `.wxs` whose dialogs would run a custom action
  (`DoAction`), point the install elsewhere (`SetTargetPath`), change features, set any property
  but the scope's, or use a control a person can type a value into, a bitmap or an icon, is refused;
- every sequence action is a standard action (never `ForceReboot` or `ScheduleReboot`) or a custom
  action the `.wxs` schedules in that sequence, on its condition;
- no row in a table a seaworthy MSI never uses (`Binary`, `SelfReg`, `MsiEmbeddedChainer`,
  `MsiEmbeddedUI`, COM and advertised file-type registrations, INI files, `MoveFile`,
  `DuplicateFile`, `RemoveFile`, ODBC, `LockPermissions`, the service failure-action tables,
  `Font`, `RemoveRegistry`, list, combo and list-view items, billboards, `UIText`, `ActionText`,
  `Error`), and every `Upgrade` row names the product's UpgradeCode or is
  a detect-only search the `.wxs` declares for a product it conflicts with (that product's
  UpgradeCode and property, never removing it);
- a `.wxs` with an element the check doesn't model (a WiX extension's, an `Environment` other than
  an appended `PATH`, …) is refused, so the check grows with the `.wxs`, never behind it.

Then it's signed with the same signers, its manifest and SBOM are written, and it joins
`packages.json`. The Windows runner still builds the binaries that are signed, so it's trusted for a
Windows release; the checks keep its MSI from doing more than the release declares.

The Group Policy templates define two machine policies under `HKLM\SOFTWARE\Policies\<Vendor>\…`:
`UpdatePolicy` (`auto`, `notify`, `off`), which overrides the MSI's default, and `Server`, the
machine's update server.

### macOS

`layout` stages `<Display Name>.app` and the tool directory; `package` writes the bundle's
`Contents/Info.plist` (the bundle id, the bundled program's executable,
`CFBundleShortVersionString` = `MAJOR.MINOR.PATCH`, `CFBundleVersion` = the sequence,
`LSMinimumSystemVersion`), signs the bundle ad hoc from the inside out and each binary of the tool
directory on its own, and builds:

- for a desktop app alone (`kind = "desktop"`, no `cli` program), a **dmg** with `hdiutil` (the
  app beside a link to `/Applications`). It carries no update helper: on macOS a helper is a
  LaunchDaemon, which only a pkg installs;
- for a service, a tool, or a product with `cli` programs, a **pkg** with `pkgbuild` and
  `productbuild`: the bundle in `/Applications` (pinned there: never relocated), the tool directory
  at `/usr/local/<vendor>/<product>`, a link in `/usr/local/bin` to each program a `[[programs]]`
  entry puts on `PATH` (its `command`; `linux.command` stays Linux's), a `preinstall` refusing to
  install while a product it conflicts with (`conflicts`) is installed by its pkg (`pkgutil
  --pkg-info` of its identifier, naming it and its uninstaller), and an uninstaller in the bundle
  (`Contents/Resources/uninstall`) or, without one, the tool directory (`uninstall`), which removes
  the links that still point into the product, the bundle, the tool directory and the receipt. A
  service's pkg adds the service's LaunchDaemon (as root, which
  `[product.<id>.service.macos] account = "root"` must say: a pkg creates no daemon account yet)
  and, with the helper, an on-demand helper daemon watching the update request file, with scripts
  that stop the service before an install and load the daemons after it. A tool's helper ships as
  a file only, as on Linux.

Both tools are macOS's own, so macOS outputs package on a Mac (`--platforms macos`). Without a
signer the signature is ad hoc: Gatekeeper refuses a downloaded copy until a tester clears the
quarantine (`xattr -dr com.apple.quarantine "/Applications/<name>.app"`), and the GitLab template
keeps macOS outputs out of releases. With `signing.toml`'s `[apple]` (and `defaults.apple.team-id`
pinned), the bundle is **Developer ID-signed** from the inside out with the hardened runtime and a
secure timestamp, and so is every binary of the tool directory (each launcher with
`macos.entitlements`, as the bundle's executable), every signature checked against Apple's
Developer ID requirement for the pinned team; the dmg is signed, **notarized** (`xcrun notarytool
submit --wait`), its ticket stapled (`xcrun stapler`), and Gatekeeper's assessment must accept it.
A pkg is signed by the Developer ID Installer identity (`productbuild --sign`) and notarized the
same way
([configuration.md](configuration.md#signingtoml)). The ticket is stapled to the dmg or pkg, the
outermost container; an app copied out of the dmg is checked against the notary service online.
A dmg isn't byte-reproducible (`hdiutil` writes timestamps and a UUID).

### File types

`[[product.<id>.file-types]]` registers each document type the product's `gui` program opens, as each
platform's installer registers one:

| | Linux (deb, rpm, pacman) | Windows (MSI) | macOS (the app bundle) |
|---|---|---|---|
| The type | an owner's shared-mime-info package, `/usr/share/mime/packages/<app-id>.xml`: its name, a glob per extension, its magic | an owner's `HKCR\.<ext>` default (the ProgID), `Content Type`, and `HKCR\MIME\Database\Content Type\<type>`'s `Extension` | `UTExportedTypeDeclarations` (an owner), `UTImportedTypeDeclarations` (an editor or viewer of a type that isn't Apple's): the UTI, what it conforms to, its extensions and media type |
| Its icon | an owner's `/usr/share/icons/hicolor/<size>/mimetypes/<type with / as ->.png` (and `scalable/….svg`), the name shared-mime-info gives the type | the ProgID's `DefaultIcon`, `<ProgID>.ico` in the install directory | `Contents/Resources/<UTI>.icns`, the document type's and the UTI's icon |
| The program | the menu entry's `MimeType` (every type) and `Exec` (the default verb's arguments, `%f` for the file) | `HKCR\<ProgID>` and `HKCR\.<ext>\OpenWithProgids\<ProgID>` (every role) | `CFBundleDocumentTypes`: the name, `CFBundleTypeRole`, `LSHandlerRank`, the UTI, the icon |
| Other verbs | a KDE service menu each, `/usr/share/kio/servicemenus/<app-id>-<verb>.desktop` | `HKCR\<ProgID>\shell\<verb>`, its label and `command` (`"<launcher>" <arguments>`, the file as `"%1"`); `shell`'s default the default verb | — (macOS hands an app its documents as an Apple event, not a command line) |

On Windows these are plain `HKCR` registry values, which Windows Installer writes under
`HKLM\Software\Classes` for a machine-wide install and `HKCU\Software\Classes` for a per-user one,
and removes with the product: what WiX's `<ProgId Advertise="no">` compiles to, so no advertised
`ProgId`, `Extension`, `Verb` or `MIME` row (nor COM's `Class`) is ever in the MSI, and adopt-msi
compares every one of these values, as every registry value. `OpenWithProgids`' value carries the
type's name: the shell reads the value names alone, and Windows Installer writes no empty string.
Windows Installer doesn't tell the shell the associations changed (`SHChangeNotify`): opening a file
works at once, while Explorer may show the new document icon only after it refreshes.

On Linux nothing runs at install: shared-mime-info's, desktop-file-utils' and the icon theme's own
triggers (dpkg triggers, rpm file triggers, pacman hooks) compile the MIME database, the menu's
MIME cache and the icon cache whenever a package changes their directories, and again when it's
removed; deb and rpm recommend `shared-mime-info` beside `hicolor-icon-theme`. desktop-file-validate
checks the menu entry; it doesn't read KDE's `Type=Service` menus, which are generated from the
validated verbs alone. Nemo's actions aren't written: Nemo puts the file into a command line it then
splits as a shell would, and documents no quoting of it.

A product's file types are its alone in a `seaworthy.toml` (two products registering `.trove` would
each take it from the other, and one's removal would remove the other's), unless the two conflict.

### Release versions

A release is a version and a sequence (the pipeline's counter). The version is `MAJOR.MINOR.PATCH`,
optionally followed by `-alpha`, `-beta` or `-rc`, each optionally followed by `.N`; anything wider
(`-rc1`, `-pre`, `+build`) is refused, because some package manager would order it differently from
the update helper. `seaworthy version` prints every spelling:

| Format | `1.4.0-rc.2`, sequence 812 | `1.4.0`, sequence 813 |
|---|---|---|
| deb | `1.4.0~rc.2-812` | `1.4.0-813` |
| rpm | `1.4.0~rc.2-812` | `1.4.0-813` |
| pacman | `1.4.0rc.2-812` | `1.4.0-813` |
| MSI ProductVersion | `1.4.0` | `1.4.0` |

The MSI's ProductVersion holds neither the pre-release nor the sequence; same-version upgrades are
allowed, and the installed release is recorded in the registry for the update helper.

The sequence is what lets one version ship many times: the deb revision, rpm `Release` and pacman
`pkgrel` are the sequence, so a later build of `1.4.0` installs over an earlier one as an upgrade.
dpkg, rpm and pacman all compare it as a number (`1.4.0-999` < `1.4.0-1000`), and only after the
version (`1.4.0-5000` < `1.4.1-1`). It must only grow: the CI templates use the pipeline counter
(GitLab's `CI_PIPELINE_IID`, GitHub's `run_number`), which keeps growing across branches, so a
branch's build orders after an older pipeline on the default branch.

`--build` names the version token's build metadata (often the commit): the manifests' `build`
field, so a manifest matches only the exact build the product's server names. It stays out of
versions and file names, since a commit doesn't sort; every Linux package's description carries it
instead (`Build: a1b2c3d4` on its own line for deb and rpm, `(build a1b2c3d4)` after pacman's
one-line description), where `apt show`, `dpkg -s`, `rpm -qi` and `pacman -Qi` show it, and so do
`packages.json` (`build`, `token`) and every SBOM (`seaworthy:build`). `package` refuses metadata
outside SemVer's grammar (dot-separated identifiers of `A-Z a-z 0-9 -`, at most 64 characters).

### SBOMs

Beside every installable artifact, `<artifact>.cdx.json` (CycloneDX 1.6): the artifact (package
name, version, vendor, SHA-512, format, target, sequence and build metadata), every file it installs
with its SHA-256, generated files included, and every Rust crate compiled into its binaries when
they were built with `cargo auditable`. The document is byte-reproducible (its serial number derives
from the artifact's SHA-512, its timestamp is `SOURCE_DATE_EPOCH`).

`repo` publishes them beside their artifacts only with `[defaults]`'s `publish-sboms = true`. No
client fetches one, so by default they stay in `package`'s output (the CI artifacts): yours to
match against new advisories and to hand to the customers and auditors who ask, without publishing
an inventory to everyone. (A binary still names its crates and their versions in its panic
locations, rustc's paths to their sources; the CI templates' path remapping shortens those paths,
but no stable compiler option drops the crate directories: [Source paths](#source-paths).)

### Reproducibility

Every timestamp in every archive and package is `SOURCE_DATE_EPOCH` (default 1980-01-01, at most
2106-02-07), entries are sorted, owners are root, and the rpm build host is fixed. With the pinned
nFPM a rebuild is byte-identical; the tests build everything twice to prove it. `seaworthy.toml`
refuses `$` in every text that reaches a package, because nFPM expands `$VAR` and WiX `$(…)` with no
escape.

## Signing

`signing.toml` names the signers; `seaworthy.toml` pins whose signatures count. Neither holds a
secret unless you sign with a local key file. The full schema is in
[configuration.md](configuration.md#signingtoml).

- **Release manifests** (`[[manifest]]`, one per `release-signatures` algorithm): a
  `seaworthy-release-manifest:1` beside every installable artifact, naming its product, channel,
  version, build, sequence, target, format, size and SHA-512. A signer is a local key file (tests,
  throwaway CI keys), a key in an environment variable (`key-env`), or a command that reads the
  statement on stdin and writes the signature on stdout (a KMS or a secret store's signer). Before
  anything is signed, the signers must cover exactly `release-signatures`, each key must be one of
  `release-keys` (the keys the clients embed) and pass the update helper's key intake; every
  signature is verified before it's written. A product without an update helper may list no
  `release-signatures`: then no manifest is signed.
- **Authenticode** (`[authenticode]`): osslsigncode with a local certificate and key, or a command
  (`{file}`, `{description}`), such as `scripts/ci/azure-sign.sh` for Azure Artifact Signing. Every
  signature, and its timestamp, must verify to `[defaults.authenticode]`'s subject and trust
  anchors. A signed release with Windows outputs refuses to run without an Authenticode signer:
  unsigned executables under signed manifests are what SmartScreen, AppLocker and WDAC refuse. A
  sidecar that arrives already signed keeps its signature only when it verifies to that same pinned
  identity; one signed by anyone else (a vendor's redistributable) is refused: ship it unsigned and
  seaworthy signs it.
- **The programs it runs**: packaging and checking tools (nFPM, strip, WiX, msitools, gpg, rpmsign,
  osslsigncode, the repository and macOS tools) start with an allowlisted environment (the
  system's variables: the path, home and temporary directories, locale, proxies, Windows' folders;
  never a `SEAWORTHY_*`, `ACTIONS_*`, `AZURE_*` or `AWS_*` variable or a CI token).
  `SEAWORTHY_TOOL_ENV` names more variables a site's tools need (never one of those). The
  signature checks `seaworthy` shares with the update helper (gpg and rpmkeys verifying against
  the pinned keys in a throwaway home) get an even smaller one: `PATH`, `TZ`, `LC_ALL=C`, the
  names `SEAWORTHY_TOOL_ENV` adds, and `HOME` and `GNUPGHOME` pointing at the throwaway
  directory, so no `~/.rpmmacros` or `~/.gnupg` changes how they check. Signing
  commands (`[[manifest]]` and `[authenticode]` `command`s) inherit the environment, less the keys
  `key-env` and `secret-key-env` hand over, and are the only programs given the runner's OIDC
  request token and cloud credentials. An OpenPGP key behind a gpg-agent that needs cloud
  credentials has its agent started by the custody wrapper beforehand.
- **Developer ID** (`[apple]`): the macOS bundle, then the dmg or pkg, signed by the identities
  in a keychain and notarized through a `notarytool` keychain profile; every signature checked
  against `defaults.apple.team-id` and the result assessed as Gatekeeper will. A signed release
  with macOS outputs refuses to run without it.
- **OpenPGP** (`[openpgp]`): an embedded signature on every rpm and a detached `.sig` on every
  pacman package, by a key in a gpg home or an armored secret key handed over in the environment
  (`secret-key-env`) and imported into a private throwaway gpg home for the run. Every signature
  must verify against `openpgp-keys` alone. A deb carries no signature of its own: apt trusts the
  repository's signed indexes.

Secrets named by `key-env` and `secret-key-env` are taken out of the process environment before any
tool runs, so nothing `seaworthy` starts (nFPM, strip, gpg, rpmsign, a signing command) inherits
them, and on Linux the process is made non-dumpable first. Every signing program runs with no shell,
under a deadline that covers draining its output (its whole process group is killed at the
deadline), with its output capped.

**Dev builds** (`--signing signing.toml --authenticode-only`): only `[authenticode]` signs, no
manifest or OpenPGP key is read, and the listing says so. The update helper never installs such a
build (no manifest) and `repo` refuses it.

**CI test keys** (`--ci-test-signing FILE`, with `[defaults.ci-test-keys]`): a non-release build's
manifests and rpm and pacman signatures by public test keys kept in the product's repository, which
only the product's non-release builds trust. An installed dev build's helper can then update to a
later one, and a release's never does. A test-key file holds no Authenticode signer and no secret
from the environment; `--ci-test-signing` never joins a release's `--signing`, and `repo` refuses
the result. Only a helper built with `SEAWORTHY_ALLOW_CI_TEST_KEYS=1` can trust the test keys
(`seaworthy_updater::ci_test`), and such a binary carries a marker: `verify` (on its own, or in a
`package` run without `--ci-test-signing`) refuses any binary carrying it or a test key
([threat model](threat-model.md#the-ci-test-key-mechanism)).

`seaworthy keygen` writes a throwaway release key (secret hex, mode 0600, and public hex);
`seaworthy sign-statement` is the reference command signer and a way to check a setup end to end. A
production key is generated in its custody system.

## Repositories

`seaworthy repo --packages DIR --out DIR --signing signing.toml` publishes every product's release
as `package` listed it into a new directory:

| Path | Class | What |
|---|---|---|
| `releases/<package>/<channel>/<token>/<target>/<package>.<format>` (+ `.manifest`, pacman `.sig`, `.cdx.json` with `publish-sboms`) | immutable | each installable artifact where the update helper's URL template points |
| `apt/pool/main/<package>/*.deb`, `apt/dists/<channel>/main/binary-amd64/by-hash/SHA256/<sha256>` | immutable | the debs, and every index under its hash |
| `apt/dists/<channel>/main/binary-amd64/Packages{,.gz}`, `apt/dists/<channel>/{Release,Release.gpg,InRelease}` | index | `dpkg-scanpackages`' stanzas and the signed `Release` |
| `rpm/<channel>/x86_64/Packages/*.rpm`, `repodata/<sha256>-*.xml.gz` | immutable | the rpms and `createrepo_c`'s metadata |
| `rpm/<channel>/x86_64/repodata/repomd.xml{,.asc}` | index | the metadata index and its signature |
| `pacman/<channel>/x86_64/*.pkg.tar.zst{,.sig}` | immutable | the packages and their signatures |
| `pacman/<channel>/x86_64/<repo>.{db,files}{.tar.zst,}{,.sig}` | index | `repo-add`'s databases, copies rather than links, each signed |
| `keys/<repo>.asc` | index | the pinned OpenPGP keys |
| `setup/<repo>-repository.{deb,deb.asc,rpm}` | index | with `[defaults.repository]`: the repository package under stable names |
| `publish-plan.json` | — | every file with its SHA-256, size and class, in upload order |

`<repo>` is the vendor in lowercase; `<token>` the version token (`1.4.0-rc.2+0a1b2c3`).

Nothing is published that a client would refuse: each listed file is read once and checked as the
clients will check it (every manifest against `release-keys`, every rpm and pacman signature against
`openpgp-keys`, the pinned keys against what apt and RHEL accept), and every index signature is
checked after signing. `repo` publishes signed releases only: an unsigned listing, a dev build and a
CI test build are refused.

- **`--previous publish-plan.json`**: the last publication's plan. No immutable path may get other
  bytes (a retried pipeline that re-signed a published version token is refused), the indexes'
  date must move forward (apt silently keeps a `Release` that's newer than the one it's offered),
  and no release may be older than the last one's, ordered as clients order releases: by version,
  then sequence (a maintenance release of an older line cut later, 1.2.1 after 1.3.0, is older
  whatever its sequence).
- **`--allow-older`**: a deliberate rollback (the older release's packages published again, dated
  now); the plan records it for `publish`.
- **`--date`**: the indexes' date (default now; never in the future, which apt refuses).

The repositories hold the latest release of each product only; an older one stays installable from
its file in `releases/` for the retention period.

**The repository package.** With `[defaults.repository]`, `package` also builds `<vendor>-repository`
(deb `all`, rpm `noarch`): the pinned OpenPGP keys and a repository definition (a deb822 source whose
`Signed-By:` is that keyring alone; a `.repo` with `gpgcheck=1` and `repo_gpgcheck=1`) as
configuration files. An administrator installs it once from `setup/`; it upgrades through the
repositories like any package, which is how a key rotation reaches machines. No product depends on
it: on a mirrored or air-gapped host its definition would point at the public URL. Arch has no
repository package: a `pacman.conf` section with `SigLevel = Required` and `pacman-key --lsign-key`
are the administrator's.

**Rotating the OpenPGP key:** pin the new key beside the current one and publish (machines'
repository packages, `keys/<repo>.asc` and the update helper built from that `seaworthy.toml` now
trust both); once machines have upgraded, switch `signing.toml`'s `[openpgp]` to the new key and
publish; later drop the old key. Hosts set up by hand need the new key from their administrators
before the switch, and rpm keeps an imported key until it's removed (`rpm -e gpg-pubkey-<keyid>`).

## Publishing

`seaworthy publish --repo DIR --target publish.toml` (feature `publish-s3`, on by default) uploads
what `repo` built to an S3-compatible store, under `publish.toml`'s prefix. The credentials come from
`SEAWORTHY_S3_ACCESS_KEY_ID`, `SEAWORTHY_S3_SECRET_ACCESS_KEY` and optionally
`SEAWORTHY_S3_SESSION_TOKEN`, never from a file, and are never printed.

1. **Before anything is uploaded**, everything that could refuse the publication is checked: every
   file against the plan (nothing unplanned, every path under the repository's own directories), the
   repository package's URL against `public-url`, the published plans (the current one and the
   history in `plans/`) for this repository and an older date (an identical current plan means
   already published) and no older release by (version, sequence); no path any of those plans
   published as immutable gets other bytes or another class (the plans outlive pruning, so a pruned
   path is never republished with other bytes); and every immutable path against the bucket by the
   store's own checksum of the object (`x-amz-checksum-sha256`), else its bytes, read under a
   deadline sized by the object and never past its stated size (never the `x-amz-meta-sha256`
   metadata `publish` writes beside it, which whoever writes the bucket sets): present with the same
   bytes, it's skipped; with other bytes, the publication is refused.
2. **Then, in order:** the missing immutable files, create-only (`If-None-Match: *`) with
   `Cache-Control: public, max-age=31536000, immutable`; the plan into `plans/` (from here on it may
   be live); the indexes in the plan's order with a short `max-age` (`index-max-age-seconds`,
   default 60); and last `publish-plan.json`, after checking no other publication moved it meanwhile,
   written with `If-Match` on the version read at the start (create-only when there was none).
   Every upload carries its SHA-256, which the store verifies, and is read back at once: its size,
   `Content-Type` and `Cache-Control` must be what was sent, and its bytes that SHA-256 (the
   store's checksum, else read and hashed).
3. **Afterwards**, every index, every release manifest, every file this run uploaded (packages
   included) and the plan are fetched back through `public-url` (with a cache-busting query) and
   compared byte for byte. Every transfer, upload, read or fetch-back, has a deadline of two minutes
   plus its size at 256 KiB/s.
4. **Pruning:** a file the current plan doesn't list is deleted once the retention period
   (`retention-days`, default 30) has passed since the plan after the last one listing it went live;
   a file no plan ever listed, since it was written, unless it predates the first plan in `plans/`
   (on a first publication into a non-empty prefix, every such file): that's not this publisher's,
   never deleted, only named. Only keys under the repository's own directories are ever deleted,
   and `plans/` is kept. A pruning failure is reported apart (exit 1 after the publication is
   reported) and doesn't undo the publication; `--no-prune` skips it.

`--dry-run` checks everything (the files, the store, the public URL) and reports what would be
uploaded and pruned, uploading and deleting nothing. A failed publication is re-run as is: files
already up are skipped, and the indexes and the pointer go up. Run one publication at a time (a CI
resource group): create-only uploads stop two writers from overwriting each other's immutable files,
but two plans racing for the indexes would interleave.

The store and its CDN are the operator's: create a credential with object read, write and delete on
the bucket alone (pruning deletes), serve the prefix through a domain whose cache honours the
objects' `Cache-Control`, and set `public-url` so every publication is checked from there.

## Setting machines up

With `[defaults.repository]` (`url = "https://files.example.com/packages"`, the vendor `Acme`):

```sh
# Debian and Ubuntu
curl -fsSLO https://files.example.com/packages/setup/acme-repository.deb
sudo apt install ./acme-repository.deb && sudo apt update

# RHEL, Rocky, Alma, Fedora
sudo rpm --import https://files.example.com/packages/keys/acme.asc
sudo dnf install https://files.example.com/packages/setup/acme-repository.rpm

# Arch Linux
curl -fsSL https://files.example.com/packages/keys/acme.asc | sudo pacman-key --add -
sudo pacman-key --lsign-key <fingerprint>
printf '\n[acme]\nSigLevel = Required\nServer = https://files.example.com/packages/pacman/stable/$arch\n' \
  | sudo tee -a /etc/pacman.conf
```

Compare the key's fingerprint with one the vendor publishes elsewhere before trusting it; the setup
deb's detached signature checks with `gpgv --keyring <dearmored key> acme-repository.deb.asc
acme-repository.deb`.

## Migrating an existing product

A product that already shipped packages built by another tool has an installed base that knows it
by several identities. seaworthy derives each of them from `seaworthy.toml`, under its own rules and
namespaces, so a new product can take them as they come; a migrating product must make each one
equal to what its machines carry, or its first seaworthy release installs beside the old product
instead of upgrading it, or never reaches the machines at all. Check every row before that release:

| Identity | What seaworthy uses | When it differs from the installed one |
|---|---|---|
| MSI UpgradeCode | `upgrade-code`, else a code derived from the vendor and the product id. Another tool derives its codes another way, so the derived one is never the code its MSIs carry. | The MSI installs beside the old product: two entries in Programs and Features, two copies of the service. **Pin `upgrade-code`** to the code the shipped MSIs carry (`msiinfo export <old>.msi Property` with msitools, or the `Property` table in Orca). `seaworthy check` notes every product with an `msi` output and no `upgrade-code`. |
| MSI ProductVersion | `MAJOR.MINOR.PATCH`; Windows Installer compares the first three fields only, allows the same version again and refuses a downgrade. | The first release is refused as a downgrade unless its version compares at or above the installed one on those three fields (a build counter the old versions kept in the third field, say). |
| MSI component GUIDs | Derived from the UpgradeCode and each file. | Nothing to do: the major upgrade removes the old product before it installs (`afterInstallInitialize`), so the two never share a component. |
| MSI scope | `[product.<id>.msi] install-scope`: per machine by default; `user` or `either` installs per user ([Install scope](#install-scope)). | Windows Installer upgrades a product only in the context it was installed in: a per-user installation of the old product isn't found by a machine-wide upgrade (or the other way round), and the two stay installed side by side. Keep the old product's scope, or remove the old installations first. |
| Package names | `<vendor>-<id>` in lowercase, for deb, rpm and pacman. | apt, dnf and pacman see an unrelated package: both stay installed and collide on shared paths (`/usr/bin/<command>`, units), and the update helper doesn't find the installed release. Choose `vendor` and the product id so the name is the old one, or name the old package in `linux.replaces` (every format then conflicts with it and replaces it), or retire it on each machine. |
| Service names | `[product.<id>.service]`'s `name`: the SCM name, the systemd unit's basename, the LaunchDaemon's label; with `state-directory` (systemd `StateDirectory=`) and the sandbox `user`. | The old service keeps running beside the new one wherever the old package or product survives, and a new state directory or user starts the service without its state, or without the right to it. Keep all three. |
| Install directories | `/opt/<vendor>/<id>` (lowercase), `%ProgramFiles%\<Vendor>\<windows-directory>`, `/Applications/<Display Name>.app`, `/usr/local/<vendor>/<id>` (lowercase); state, staging and logs under `%ProgramData%\<Vendor>\<windows-directory>`. | Files move: whatever names the old paths (scripts, firewall rules, monitoring, allow-lists) stops matching, and state left under the old directory isn't carried over. |
| macOS bundle id | `bundle-id`, which is also the pkg's identifier. | macOS keys permissions and preferences to the bundle id, and the installer upgrades an app only under the same identifier. Keep it. |
| Update policy | `HKLM\SOFTWARE\Policies\<Vendor>\<windows-directory>` (Group Policy), `HKLM\SOFTWARE\<Vendor>\<windows-directory>` (the MSI's `UPDATES=` and `SERVER=`), `/etc/<vendor>/<id>/policy.toml`. | Administrators' policies stop applying, silently: an `off` their policy set no longer holds. Keep `vendor` and `windows-directory` so the keys are the ones administrators already set, or have them deploy the new Group Policy templates first. |
| The release key | `release-keys`, compiled into the update helper, verifying `seaworthy-release-manifest:1` manifests. | An update helper built by another tool verifies its own manifest format and keys: it never installs a seaworthy release. The first seaworthy release reaches machines through a channel they already trust (the package repositories, below; an administrator; the old tool's own update path); from then on the seaworthy-built helper updates them. An existing ML-DSA-87, ECDSA P-256 or Ed25519 key pair can stay the release key, its public key written as `seaworthy keygen --public` writes one. |
| The OpenPGP key | `openpgp-keys`: rpm and pacman signatures and every repository index. | Machines' keyrings refuse what a new key signed. Sign with the key they trust, or rotate it as above ("Rotating the OpenPGP key"). |
| Repository URLs | `[defaults.repository]`'s `url`; the layout under it (`apt/`, `rpm/<channel>/x86_64`, `pacman/<channel>/x86_64`); the repository package's `/etc/apt/sources.list.d/<repo>.sources`, `/usr/share/keyrings/<repo>-archive-keyring.asc` and `/etc/yum.repos.d/<repo>.repo`. | Machines keep fetching the old URL and layout and never see a seaworthy release. Publish where they look, or ship one last release through the old repository that installs `<vendor>-repository` and removes the old source definition (apt refuses one repository listed twice with different `Signed-By` keyrings). |

Then prove the upgrade on a machine with the last old release installed, for each format: one
product left in Programs and Features (or one package in `dpkg -l`, `rpm -qa`, `pacman -Q`), its
service running under its old name with its state, the administrator's policy still read, and the
seaworthy-built update helper installing the release after it.
