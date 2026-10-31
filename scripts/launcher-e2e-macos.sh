#!/usr/bin/env bash
# scripts/launcher-e2e-macos.sh — seaworthy-launcher end to end on Apple
# Silicon macOS: the fixture product (crates/seaworthy-launcher/e2e) laid out
# as a macOS product — the launcher in an app bundle's Contents/MacOS, one
# core per CPU target in Contents/Frameworks, each built in its own target
# directory with `-C target-cpu=<cpu>` and nothing else — and checked on
# real binaries:
#
#   - the Mach-O records survive the shipped profile (thin LTO, strip): each
#     core's __DATA,__cpureq and the launcher's __DATA,__cpulist read back;
#   - the launcher skips the apple-m4 core (its record carries v8.5a and
#     later, which macOS reports no signal for) and runs apple-m1;
#   - SEAWORTHY_CORE: apple-m1 runs, apple-m4 is refused (78), a CPU name
#     that isn't one of the product's is refused (64);
#   - started through a symlink outside the bundle, it still finds its cores
#     (the launcher resolves its own path);
#   - argument, exit-code, panic (101) and unflushed-stdout pass-through;
#   - a missing apple-m1 core, or one carrying another build's record, is a
#     damaged install (74), never "CPU too old";
#   - the build refuses a core enabling a feature no aarch64 record can name;
#   - the seaworthy CLI packages the fixture as a desktop product in a disk
#     image: verify, layout and package write the bundle's Info.plist, sign
#     it ad hoc and build the dmg; the image mounts with the app beside a
#     link to /Applications, the bundle and the image pass `codesign
#     --verify --strict`, the Info.plist names the bundle and the release,
#     and the app runs from the mounted image;
#   - the CLI packages it as a service in a pkg: expanded, the package
#     names its identifier and version, the payload holds the signed bundle
#     (launcher, helper, uninstaller) and both LaunchDaemons (valid plists,
#     the helper's watching the request file), the scripts parse, and the
#     distribution is Apple Silicon's. Whether passwordless sudo works is
#     reported: scripts/macos-pkg-install.sh needs it;
#   - the CLI packages it as a command-line tool in a pkg ([[programs]], no
#     app bundle): the payload holds the tool directory
#     (/usr/local/acme/demo: bin/demo, its cores in Frameworks, the
#     uninstaller), each binary signed on its own, and the link
#     /usr/local/bin/acme-demo to the launcher, which runs from there;
#   - a FIPS product: the cores built with the AWS-LC FIPS module
#     (seaworthy-crypto's `fips` feature), which AWS-LC builds as a dylib
#     off Linux, linked with @loader_path and unstripped, as the build plan
#     builds them; the CLI verifies the module and each core's symbol table,
#     ships the module once in the bundle's Contents/Frameworks
#     (sidecars.macos) and signs it with the bundle; nm agrees the core
#     imports the module and defines no AWS-LC; the app, run from its
#     mounted dmg, finds the module and passes its power-on self-tests
#     (fips=ok); the CLI refuses that core stripped, and relinked with a
#     definition of the non-FIPS AWS-LC's.
#
#   scripts/launcher-e2e-macos.sh
#
# Requirements: Apple Silicon macOS 11 or newer; bash 4.4 or newer (macOS's
# /bin/bash is 3.2: put Homebrew's bash first on PATH); git; rustup with the
# toolchain rust-toolchain.toml pins and its aarch64-apple-darwin target;
# file(1); Xcode's command line tools (codesign, hdiutil, pkgbuild,
# productbuild, pkgutil, plutil); for the FIPS product, what the AWS-LC FIPS
# module builds with (CMake, Go, Perl). Elsewhere it SKIPs, or fails with
# SEAWORTHY_LAUNCHER_E2E_REQUIRED=1 (CI). Builds go to
# ${CARGO_TARGET_DIR:-target}/launcher-e2e-macos, the seaworthy CLI to
# ${CARGO_TARGET_DIR:-target} itself.
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"

cd "$(git rev-parse --show-toplevel)"
FIXTURE=crates/seaworthy-launcher/e2e
OUT="${CARGO_TARGET_DIR:-$PWD/target}/launcher-e2e-macos"
TARGET=aarch64-apple-darwin
CPUS=(apple-m4 apple-m1)
REQUIRED="${SEAWORTHY_LAUNCHER_E2E_REQUIRED:-0}"

fail() { echo "launcher-e2e-macos: FAIL: $*" >&2; exit 1; }
ok() { echo "launcher-e2e-macos: ok    $*"; }
skip() {
    if [ "$REQUIRED" = 1 ]; then fail "$* (SEAWORTHY_LAUNCHER_E2E_REQUIRED=1)"; fi
    echo "launcher-e2e-macos: SKIP  $*"
}

[ "$(uname -s)-$(uname -m)" = "Darwin-arm64" ] || { skip "not an Apple Silicon macOS host"; exit 0; }

build() { # <target-dir> <rustflags> <package> [cargo args…]
    local dir="$1" flags="$2" package="$3"
    shift 3
    # MACOSX_DEPLOYMENT_TARGET as the build plan sets it (defaults.macos-minimum,
    # 11.0 in these fixtures): without it AWS-LC's CMake build targets the SDK's
    # macOS, which seaworthy verify refuses.
    MACOSX_DEPLOYMENT_TARGET=11.0 RUSTFLAGS="$flags" CARGO_TARGET_DIR="$dir" cargo build --quiet --release --locked \
        --manifest-path "$FIXTURE/Cargo.toml" --target "$TARGET" -p "$package" "$@"
}

# run <expected exit> <expected stdout+stderr substring> <command…>
run() {
    local want_rc="$1" want_text="$2"
    shift 2
    local out rc=0
    out="$("$@" 2>&1)" || rc=$?
    [ "$rc" = "$want_rc" ] || fail "$* exited $rc (expected $want_rc): $out"
    case "$out" in *"$want_text"*) ;; *) fail "$*: expected \"$want_text\" in: $out" ;; esac
}

# Detaches the image at <mount>. macOS may still hold a file on it for a
# moment after its app ran (its security scan of freshly loaded code:
# "Resource busy"), so wait for that, then force.
detach() { # <mount>
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        hdiutil detach "$1" >/dev/null 2>&1 && return 0
        sleep 2
    done
    hdiutil detach "$1" -force >/dev/null
}

rm -rf "${OUT:?}/Demo.app" "${OUT:?}/damaged" "${OUT:?}/mixed" "${OUT:?}/bin"
build "$OUT/launcher" "" demo
build "$OUT/launcher" "" inspect
for cpu in "${CPUS[@]}"; do
    build "$OUT/core-$cpu" "-C target-cpu=$cpu" demo_core
done
ok "built the launcher (apple-m1 default) and cores ${CPUS[*]}"

APP="$OUT/Demo.app/Contents"
mkdir -p "$APP/MacOS" "$APP/Frameworks"
cp "$OUT/launcher/$TARGET/release/demo" "$APP/MacOS/demo"
for cpu in "${CPUS[@]}"; do
    cp "$OUT/core-$cpu/$TARGET/release/libdemo_core.dylib" "$APP/Frameworks/libdemo_core_$cpu.dylib"
done
DEMO="$APP/MacOS/demo"
INSPECT="$OUT/launcher/$TARGET/release/inspect"

# The records, read back from the shipped (stripped, LTO) Mach-O files.
file "$DEMO" | grep -q "Mach-O 64-bit executable arm64" || fail "$DEMO: $(file "$DEMO")"
run 0 "cpus=apple-m4,apple-m1" "$INSPECT" cpulist "$DEMO"
for cpu in "${CPUS[@]}"; do
    core="$APP/Frameworks/libdemo_core_$cpu.dylib"
    run 0 "target=$TARGET
cpu=$cpu" "$INSPECT" cpureq "$core"
    run 0 "neon" "$INSPECT" cpureq "$core"
done
run 0 "v8.7a" "$INSPECT" cpureq "$APP/Frameworks/libdemo_core_apple-m4.dylib"
ok "the Mach-O records survive thin LTO and strip (__DATA,__cpureq, __DATA,__cpulist)"

# Selection: apple-m4 is skipped (no signal for v8.5a and later), apple-m1 runs.
run 0 "core=apple-m1" "$DEMO"
# (What else it lacks depends on the chip: an M1 also lacks bf16, i8mm, …)
run 0 "skipped apple-m4: needs" env SEAWORTHY_LAUNCHER_DEBUG=1 "$DEMO"
run 0 "v8.7a" env SEAWORTHY_LAUNCHER_DEBUG=1 "$DEMO"
run 0 "core=apple-m1" env SEAWORTHY_CORE=apple-m1 "$DEMO"
run 78 "can't run that build" env SEAWORTHY_CORE=apple-m4 "$DEMO"
run 64 "is not one of this program's builds" env SEAWORTHY_CORE=x86-64-v3 "$DEMO"
ok "the launcher skips apple-m4 and runs apple-m1; SEAWORTHY_CORE and its refusals"

# Through a symlink outside the bundle: the cores are found beside the real file.
mkdir -p "$OUT/bin"
ln -s "$DEMO" "$OUT/bin/demo"
run 0 "core=apple-m1" "$OUT/bin/demo"
ok "started through a symlink, it finds the bundle's cores"

# Pass-through.
run 0 "args=args a b c" "$DEMO" args a "b c"
run 7 "core=apple-m1" "$DEMO" exit 7
run 101 "the core panicked on request" "$DEMO" panic
run 0 "no newline at the end" "$DEMO" partial-line
ok "arguments, exit codes, panics and unflushed stdout pass through"

# A damaged install is never "CPU too old".
cp -R "$OUT/Demo.app" "$OUT/damaged"
rm "$OUT/damaged/Contents/Frameworks/libdemo_core_apple-m1.dylib"
run 74 "repair or reinstall" "$OUT/damaged/Contents/MacOS/demo"
cp -R "$OUT/Demo.app" "$OUT/mixed"
cp "$APP/Frameworks/libdemo_core_apple-m4.dylib" "$OUT/mixed/Contents/Frameworks/libdemo_core_apple-m1.dylib"
run 74 "carries the record of another build" "$OUT/mixed/Contents/MacOS/demo"
ok "a missing or mismatched apple-m1 core is a damaged install (74)"

# The build refuses what no aarch64 record could name.
out="$(RUSTFLAGS="-C target-cpu=apple-m1 -C target-feature=+avx2" CARGO_TARGET_DIR="$OUT/refused" \
    cargo build --quiet --release --locked --manifest-path "$FIXTURE/Cargo.toml" --target "$TARGET" \
    -p demo_core 2>&1)" && fail "a core enabling +avx2 built: $out"
case "$out" in *"enables avx2, which seaworthy-levels has no row for"*) ;; *) fail "unexpected refusal: $out" ;; esac
ok "the build refuses a feature no aarch64 record can name"

# The seaworthy CLI on the Mac: the fixture as a desktop product in a dmg.
TARGET_ROOT="${CARGO_TARGET_DIR:-$PWD/target}"
cargo build --quiet --locked -p seaworthy --bin seaworthy
SEAWORTHY="$TARGET_ROOT/debug/seaworthy"
PROJECT="$OUT/dmg-project"
rm -rf "${PROJECT:?}"
mkdir -p "$PROJECT/artifacts/$TARGET/launcher"
cp "$DEMO" "$PROJECT/artifacts/$TARGET/launcher/demo"
for cpu in "${CPUS[@]}"; do
    mkdir -p "$PROJECT/artifacts/$TARGET/cores/$cpu"
    cp "$OUT/core-$cpu/$TARGET/release/libdemo_core.dylib" "$PROJECT/artifacts/$TARGET/cores/$cpu/"
done
cat > "$PROJECT/seaworthy.toml" <<'TOML'
[defaults]
vendor = "Acme"
targets = ["x86-64-v3"]
macos-targets = ["apple-m4", "apple-m1"]
channel = "stable"
maintainer = "Acme Packaging <packages@example.com>"
license = "MIT"

[product.demo]
display-name = "Acme Demo"
description = "The launcher's end-to-end fixture."
executable = "demo"
core = "demo_core"
kind = "desktop"
outputs = ["dmg"]
updates.default = "off"

[product.demo.macos]
bundle-id = "com.example.acme.demo"
category = "public.app-category.developer-tools"
TOML
"$SEAWORTHY" verify --config "$PROJECT/seaworthy.toml" --artifacts "$PROJECT/artifacts" >/dev/null ||
    fail "seaworthy verify refused the macOS fixture"
"$SEAWORTHY" package --config "$PROJECT/seaworthy.toml" --artifacts "$PROJECT/artifacts" --out "$PROJECT/out" \
    --release 0.1.0 --sequence 7 || fail "seaworthy package failed"
DMG="$PROJECT/out/demo/packages/acme-demo-0.1.0-7-macos-arm64.dmg"
[ -f "$DMG" ] || fail "no $DMG"
[ -f "$DMG.cdx.json" ] || fail "no SBOM beside $DMG"
grep -q '"kind": "dmg"' "$PROJECT/out/demo/packages.json" || fail "packages.json doesn't list the dmg"
codesign --verify --strict "$DMG" || fail "the dmg's signature doesn't verify"
MOUNT="$OUT/dmg-mount"
mkdir -p "$MOUNT"
hdiutil attach -nobrowse -readonly -noautoopen -mountpoint "$MOUNT" "$DMG" >/dev/null || fail "hdiutil attach failed"
trap 'hdiutil detach "$MOUNT" -force >/dev/null 2>&1 || true' EXIT
BUNDLE="$MOUNT/Acme Demo.app"
[ -d "$BUNDLE" ] || fail "the image holds no Acme Demo.app: $(ls -la "$MOUNT")"
[ "$(readlink "$MOUNT/Applications")" = /Applications ] || fail "the image has no link to /Applications"
codesign --verify --deep --strict "$BUNDLE" || fail "the bundle's signature doesn't verify"
plist() { plutil -extract "$1" raw -o - "$BUNDLE/Contents/Info.plist"; }
[ "$(plist CFBundleIdentifier)" = com.example.acme.demo ] || fail "CFBundleIdentifier: $(plist CFBundleIdentifier)"
[ "$(plist CFBundleExecutable)" = demo ] || fail "CFBundleExecutable: $(plist CFBundleExecutable)"
[ "$(plist CFBundleShortVersionString)" = 0.1.0 ] || fail "CFBundleShortVersionString: $(plist CFBundleShortVersionString)"
[ "$(plist CFBundleVersion)" = 7 ] || fail "CFBundleVersion: $(plist CFBundleVersion)"
[ "$(plist LSMinimumSystemVersion)" = 11.0 ] || fail "LSMinimumSystemVersion: $(plist LSMinimumSystemVersion)"
run 0 "core=apple-m1" "$BUNDLE/Contents/MacOS/demo"
detach "$MOUNT" || fail "hdiutil detach failed"
trap - EXIT
ok "seaworthy packages a signed app bundle in a dmg that mounts, verifies and runs"

# The fixture as a service in a pkg, with a stand-in update helper (the
# launcher's binary: only its place is checked here; macos-pkg-install.sh
# installs the real one).
SERVICE="$OUT/pkg-project"
rm -rf "${SERVICE:?}"
mkdir -p "$SERVICE/artifacts/$TARGET/launcher" "$SERVICE/artifacts/$TARGET/helper"
cp "$DEMO" "$SERVICE/artifacts/$TARGET/launcher/demo"
cp "$DEMO" "$SERVICE/artifacts/$TARGET/helper/demo-update"
for cpu in "${CPUS[@]}"; do
    mkdir -p "$SERVICE/artifacts/$TARGET/cores/$cpu"
    cp "$OUT/core-$cpu/$TARGET/release/libdemo_core.dylib" "$SERVICE/artifacts/$TARGET/cores/$cpu/"
done
cat > "$SERVICE/seaworthy.toml" <<'TOML'
[defaults]
vendor = "Acme"
targets = ["x86-64-v3"]
macos-targets = ["apple-m4", "apple-m1"]
channel = "stable"
release-signatures = ["ml-dsa-87"]
maintainer = "Acme Packaging <packages@example.com>"
license = "MIT"

[product.agent]
display-name = "Acme Agent"
description = "The launcher's end-to-end fixture as a service."
executable = "demo"
core = "demo_core"
helper = "demo-update"
outputs = ["pkg"]
updates.default = "auto"

[product.agent.service]
name = "AcmeAgent"
account = "local-system"
arguments = ["serve"]
restart-delays = ["15s"]
state-directory = "acme/agent"

# A macOS service runs as root, said explicitly (its package creates no
# daemon account yet).
[product.agent.service.macos]
account = "root"

[product.agent.macos]
bundle-id = "com.example.acme.agent"
TOML
"$SEAWORTHY" package --config "$SERVICE/seaworthy.toml" --artifacts "$SERVICE/artifacts" --out "$SERVICE/out" \
    --release 0.1.0 --sequence 7 || fail "seaworthy package (pkg) failed"
PKG="$SERVICE/out/agent/packages/acme-agent-0.1.0-7-macos-arm64.pkg"
[ -f "$PKG" ] || fail "no $PKG"
[ -f "$PKG.cdx.json" ] || fail "no SBOM beside $PKG"
grep -q '"kind": "pkg"' "$SERVICE/out/agent/packages.json" || fail "packages.json doesn't list the pkg"
EXPANDED="$SERVICE/expanded"
pkgutil --expand-full "$PKG" "$EXPANDED" || fail "pkgutil --expand-full failed"
grep -q 'hostArchitectures="arm64"' "$EXPANDED/Distribution" || fail "the distribution isn't Apple Silicon's"
grep -q '<os-version min="11.0"/>' "$EXPANDED/Distribution" || fail "the distribution has no macOS 11.0 floor"
INFO="$EXPANDED/component.pkg/PackageInfo"
grep -q 'identifier="com.example.acme.agent"' "$INFO" || fail "PackageInfo: $(cat "$INFO")"
grep -q 'version="0.1.0-7"' "$INFO" || fail "PackageInfo: $(cat "$INFO")"
PAYLOAD="$EXPANDED/component.pkg/Payload"
INSTALLED="$PAYLOAD/Applications/Acme Agent.app"
for file in Contents/MacOS/demo Contents/MacOS/demo-update Contents/Resources/uninstall \
    Contents/Frameworks/libdemo_core_apple-m1.dylib Contents/Info.plist; do
    [ -f "$INSTALLED/$file" ] || fail "the payload has no $file: $(find "$PAYLOAD" -maxdepth 4)"
done
codesign --verify --deep --strict "$INSTALLED" || fail "the payload's bundle doesn't verify"
for label in AcmeAgent AcmeAgent-update; do
    plist="$PAYLOAD/Library/LaunchDaemons/$label.plist"
    plutil -lint "$plist" >/dev/null || fail "$label.plist isn't a valid plist"
    [ "$(plutil -extract Label raw -o - "$plist")" = "$label" ] || fail "$label.plist's Label"
done
[ "$(plutil -extract WatchPaths.0 raw -o - "$PAYLOAD/Library/LaunchDaemons/AcmeAgent-update.plist")" = \
    "/Library/Application Support/Acme/Agent/state/update-request" ] || fail "the helper's daemon watches the wrong file"
for script in preinstall postinstall; do
    [ -x "$EXPANDED/component.pkg/Scripts/$script" ] || fail "no executable $script"
    sh -n "$EXPANDED/component.pkg/Scripts/$script" || fail "$script doesn't parse"
done
sh -n "$INSTALLED/Contents/Resources/uninstall" || fail "the uninstaller doesn't parse"
ok "seaworthy packages a service as a pkg: the signed bundle, its LaunchDaemons and scripts"

# The fixture as a command-line tool in a pkg: no bundle, the tool
# directory and its PATH link.
TOOLPROJECT="$OUT/tool-project"
rm -rf "${TOOLPROJECT:?}"
mkdir -p "$TOOLPROJECT/artifacts/$TARGET/launcher"
cp "$DEMO" "$TOOLPROJECT/artifacts/$TARGET/launcher/demo"
for cpu in "${CPUS[@]}"; do
    mkdir -p "$TOOLPROJECT/artifacts/$TARGET/cores/$cpu"
    cp "$OUT/core-$cpu/$TARGET/release/libdemo_core.dylib" "$TOOLPROJECT/artifacts/$TARGET/cores/$cpu/"
done
cat > "$TOOLPROJECT/seaworthy.toml" <<'TOML'
[defaults]
vendor = "Acme"
targets = ["x86-64-v3"]
macos-targets = ["apple-m4", "apple-m1"]
channel = "stable"
maintainer = "Acme Packaging <packages@example.com>"
license = "MIT"

[product.demo]
display-name = "Acme Demo"
description = "The launcher's end-to-end fixture as a command-line tool."
kind = "tool"
outputs = ["pkg"]
updates.default = "off"

[[product.demo.programs]]
executable = "demo"
core = "demo_core"
role = "cli"
command = "acme-demo"

[product.demo.macos]
bundle-id = "com.example.acme.demo-tool"
TOML
"$SEAWORTHY" package --config "$TOOLPROJECT/seaworthy.toml" --artifacts "$TOOLPROJECT/artifacts" \
    --out "$TOOLPROJECT/out" --release 0.1.0 --sequence 7 || fail "seaworthy package (tool pkg) failed"
TOOLPKG="$TOOLPROJECT/out/demo/packages/acme-demo-0.1.0-7-macos-arm64.pkg"
[ -f "$TOOLPKG" ] || fail "no $TOOLPKG"
grep -q '"kind": "pkg"' "$TOOLPROJECT/out/demo/packages.json" || fail "packages.json doesn't list the tool's pkg"
TOOLEXPANDED="$TOOLPROJECT/expanded"
pkgutil --expand-full "$TOOLPKG" "$TOOLEXPANDED" || fail "pkgutil --expand-full (tool) failed"
grep -q 'identifier="com.example.acme.demo-tool"' "$TOOLEXPANDED/component.pkg/PackageInfo" ||
    fail "PackageInfo: $(cat "$TOOLEXPANDED/component.pkg/PackageInfo")"
TOOLPAYLOAD="$TOOLEXPANDED/component.pkg/Payload"
[ ! -e "$TOOLPAYLOAD/Applications" ] || fail "a tool's payload holds an app bundle"
TOOLDIR="$TOOLPAYLOAD/usr/local/acme/demo"
for file in bin/demo Frameworks/libdemo_core_apple-m1.dylib Frameworks/libdemo_core_apple-m4.dylib uninstall; do
    [ -f "$TOOLDIR/$file" ] || fail "the tool's payload has no $file: $(find "$TOOLPAYLOAD" -maxdepth 6)"
done
for file in bin/demo Frameworks/libdemo_core_apple-m1.dylib; do
    codesign --verify --strict "$TOOLDIR/$file" || fail "$file's signature doesn't verify"
done
[ "$(readlink "$TOOLPAYLOAD/usr/local/bin/acme-demo")" = /usr/local/acme/demo/bin/demo ] ||
    fail "the payload's /usr/local/bin/acme-demo isn't a link to the launcher"
for script in preinstall postinstall; do
    sh -n "$TOOLEXPANDED/component.pkg/Scripts/$script" || fail "the tool's $script doesn't parse"
done
sh -n "$TOOLDIR/uninstall" || fail "the tool's uninstaller doesn't parse"
run 0 "core=apple-m1" "$TOOLDIR/bin/demo"
ok "seaworthy packages a command-line tool as a pkg: the tool directory, its signatures and its PATH link"
if sudo -n true 2>/dev/null; then
    echo "launcher-e2e-macos: info  passwordless sudo works here (scripts/macos-pkg-install.sh can run)"
else
    echo "launcher-e2e-macos: info  sudo needs a password here (scripts/macos-pkg-install.sh can't run)"
fi

# A FIPS product: the module's dylib beside the cores in the bundle. Not
# stripped, as the build plan builds a core: verify reads its local symbols.
fips_flags() { echo "-C target-cpu=$1 -C link-arg=-Wl,-rpath,@loader_path"; }
for cpu in "${CPUS[@]}"; do
    CARGO_PROFILE_RELEASE_STRIP=false build "$OUT/fips-core-$cpu" "$(fips_flags "$cpu")" demo_core --features fips
done
FIPSPROJECT="$OUT/fips-project"
rm -rf "${FIPSPROJECT:?}"
mkdir -p "$FIPSPROJECT/artifacts/$TARGET/launcher"
cp "$DEMO" "$FIPSPROJECT/artifacts/$TARGET/launcher/demo"
MODULE="$(find "$OUT/fips-core-${CPUS[0]}/$TARGET/release/build" -type f -name 'libaws_lc_fips_*_crypto.dylib' | head -1)"
[ -n "$MODULE" ] || fail "the FIPS build left no libaws_lc_fips_*_crypto.dylib"
for cpu in "${CPUS[@]}"; do
    mkdir -p "$FIPSPROJECT/artifacts/$TARGET/cores/$cpu"
    cp "$OUT/fips-core-$cpu/$TARGET/release/libdemo_core.dylib" "$FIPSPROJECT/artifacts/$TARGET/cores/$cpu/"
    cp "$MODULE" "$FIPSPROJECT/artifacts/$TARGET/cores/$cpu/"
done
cat > "$FIPSPROJECT/seaworthy.toml" <<'TOML'
[defaults]
vendor = "Acme"
targets = ["x86-64-v3"]
macos-targets = ["apple-m4", "apple-m1"]
channel = "stable"
maintainer = "Acme Packaging <packages@example.com>"
license = "MIT"
fips = true

[product.demo]
display-name = "Acme Demo"
description = "The launcher's end-to-end fixture, FIPS."
executable = "demo"
core = "demo_core"
kind = "desktop"
outputs = ["dmg"]
updates.default = "off"
sidecars.macos = ["libaws_lc_fips_*_crypto.dylib"]

[product.demo.macos]
bundle-id = "com.example.acme.demo"
TOML
"$SEAWORTHY" package --config "$FIPSPROJECT/seaworthy.toml" --artifacts "$FIPSPROJECT/artifacts" \
    --out "$FIPSPROJECT/out" --release 0.1.0 --sequence 7 >/dev/null || fail "seaworthy package (FIPS) failed"
# package verified it; the platform's own nm reads the core the same way:
# the module's symbols imported, no AWS-LC or ring defined, though the build
# compiled a second AWS-LC when rustls's feature asks for one.
FIPSCORE="$FIPSPROJECT/artifacts/$TARGET/cores/apple-m1/libdemo_core.dylib"
imported="$(nm -u "$FIPSCORE")" || fail "nm -u failed on the FIPS core"
defined="$(nm -U "$FIPSCORE")" || fail "nm -U failed on the FIPS core"
case "$imported" in *_aws_lc_fips_*) ;; *) fail "the FIPS core imports nothing of the module: $imported" ;; esac
if printf '%s\n' "$defined" | grep -E ' _(aws_lc_|awslc_|ring_core_)'; then
    fail "the FIPS core defines those AWS-LC or ring symbols"
fi
if compgen -G "$OUT/fips-core-apple-m1/$TARGET/release/deps/libaws_lc_sys-*.rlib" >/dev/null; then
    echo "launcher-e2e-macos: info  aws-lc-sys was compiled into the FIPS build, and isn't linked"
else
    echo "launcher-e2e-macos: info  aws-lc-sys wasn't compiled into the FIPS build"
fi
FIPSDMG="$FIPSPROJECT/out/demo/packages/acme-demo-0.1.0-7-macos-arm64.dmg"
[ -f "$FIPSDMG" ] || fail "no $FIPSDMG"
mkdir -p "$MOUNT"
hdiutil attach -nobrowse -readonly -noautoopen -mountpoint "$MOUNT" "$FIPSDMG" >/dev/null || fail "hdiutil attach (FIPS) failed"
trap 'hdiutil detach "$MOUNT" -force >/dev/null 2>&1 || true' EXIT
BUNDLE="$MOUNT/Acme Demo.app"
[ -f "$BUNDLE/Contents/Frameworks/$(basename "$MODULE")" ] || fail "the bundle has no $(basename "$MODULE"): $(ls "$BUNDLE/Contents/Frameworks")"
codesign --verify --deep --strict "$BUNDLE" || fail "the FIPS bundle's signature doesn't verify"
otool -L "$BUNDLE/Contents/Frameworks/libdemo_core_apple-m1.dylib" | grep -q "@rpath/$(basename "$MODULE")" ||
    fail "the core doesn't load the module through @rpath: $(otool -L "$BUNDLE/Contents/Frameworks/libdemo_core_apple-m1.dylib")"
out="$("$BUNDLE/Contents/MacOS/demo" 2>&1)" || fail "the FIPS app failed: $out"
case "$out" in *"core=apple-m1"*"fips=ok"*) ;; *) fail "the FIPS app ran without passing the module's self-tests: $out" ;; esac
detach "$MOUNT" || fail "hdiutil detach (FIPS) failed"
trap - EXIT
ok "a FIPS product ships the module's dylib in the bundle; the app runs it from the dmg (fips=ok)"

# The real core, refused for what verify's symbol check is for. Stripped, it
# still lists its imports, so only the missing local symbols can refuse it.
REFUSED="$OUT/fips-refused"
rm -rf "${REFUSED:?}"
cp -R "$FIPSPROJECT/artifacts" "$REFUSED"
REFUSEDCORE="$REFUSED/$TARGET/cores/apple-m1/libdemo_core.dylib"
strip -x "$REFUSEDCORE" 2>/dev/null || fail "strip -x failed on the FIPS core"
imported="$(nm -u "$REFUSEDCORE")" || fail "nm -u failed on the stripped FIPS core"
case "$imported" in *_aws_lc_fips_*) ;; *) fail "the stripped FIPS core lost its imports: $imported" ;; esac
run 1 "is stripped (no local symbols)" "$SEAWORTHY" verify --config "$FIPSPROJECT/seaworthy.toml" --artifacts "$REFUSED"
# Relinked with a definition of the non-FIPS module's: one object more, and
# cargo rebuilds only the core (the flags after -- reach no dependency). It
# overwrites the build's core, which nothing below needs.
printf '__attribute__((used)) int aws_lc_0_0_0_EVP_sha256(void) { return 0; }\n' >"$OUT/fips-foreign.c"
MACOSX_DEPLOYMENT_TARGET=11.0 cc -arch arm64 -c "$OUT/fips-foreign.c" -o "$OUT/fips-foreign.o" ||
    fail "cc failed on the foreign object"
CARGO_PROFILE_RELEASE_STRIP=false MACOSX_DEPLOYMENT_TARGET=11.0 RUSTFLAGS="$(fips_flags apple-m1)" CARGO_TARGET_DIR="$OUT/fips-core-apple-m1" \
    cargo rustc --quiet --release --locked --manifest-path "$FIXTURE/Cargo.toml" --target "$TARGET" \
    -p demo_core --lib --features fips -- -C "link-arg=$OUT/fips-foreign.o" || fail "the relink with the foreign object failed"
cp "$OUT/fips-core-apple-m1/$TARGET/release/libdemo_core.dylib" "$REFUSEDCORE"
run 1 "non-FIPS AWS-LC (aws-lc-sys) symbols, e.g. aws_lc_0_0_0_EVP_sha256" \
    "$SEAWORTHY" verify --config "$FIPSPROJECT/seaworthy.toml" --artifacts "$REFUSED"
ok "verify refuses the real FIPS core stripped, and with a non-FIPS AWS-LC symbol linked in"

echo "launcher-e2e-macos: all checks passed"
