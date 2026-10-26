#!/usr/bin/env bash
# scripts/macos-pkg-install.sh — a macOS service's pkg installed for real:
# the e2e fixture as a service product with seaworthy-updater's real update
# helper (demo_helper, a throwaway release key compiled in), built with the
# CI template's build step, packaged by the seaworthy CLI with signed
# manifests, then installed on this Mac with sudo:
#
#   1. release 1.0.0-rc.1 (pkg version `1.0.0~rc.1-1`) installed by hand:
#      the receipt names it; launchd runs the service (its log shows the
#      chosen core) and has the helper's daemon loaded; the state and
#      staging directories are root's and private; the bundle verifies;
#   2. the update helper upgrades to 1.0.0: the service writes its request
#      file (here: root writes it, as the service would), launchd starts
#      the helper (WatchPaths), the helper learns 1.0.0 from the lab
#      server's required-version endpoint (conformance_server on loopback),
#      fetches the pkg and its manifest from the lab's release tree,
#      verifies them and runs `installer`; the receipt names 1.0.0, the
#      helper's log says so, the service runs again under a new process
#      and the helper's daemon stays loaded;
#   3. refused releases never reach `installer` (the lab naming 1.0.1): a
#      manifest for another format, a tampered pkg under its valid
#      manifest, and (the lab naming 1.0.0-rc.1) a downgrade; the receipt
#      and the service's process stay, the helper's log names each refusal;
#   4. the administrator's policy file (/etc/acme/agent/policy.toml,
#      through macOS's /etc link): `off` installs nothing, and a file
#      someone else could write counts as `off`;
#   5. failed updates: 1.0.1 whose postinstall exits 1 (`installer` fails
#      after the preinstall stopped the service and the payload replaced
#      its files: the postinstall starts it anyway), then 1.0.2 whose
#      preinstall exits 1 once it has stopped the service (no postinstall
#      runs: the helper starts it again); each time launchd runs the
#      service again and the helper's daemon stays loaded, and a request
#      right after the first backs off instead of retrying; then 1.0.3
#      installs over them (the helper rolls forward);
#   6. the bundle's uninstaller (--purge) removes the daemons, the app, the
#      receipt, the state and the logs.
#
#   scripts/macos-pkg-install.sh
#
# Apple Silicon macOS with passwordless sudo only (a GitHub-hosted macOS
# runner, the lab workflow's macOS pkg install job: a throwaway VM, since
# it installs system daemons); elsewhere it SKIPs, or fails with
# SEAWORTHY_MACOS_INSTALL_REQUIRED=1. Needs bash 4.4 or newer (Homebrew's),
# rustup with rust-toolchain.toml's toolchain and Xcode's command line
# tools. Builds go to ${CARGO_TARGET_DIR:-target}/macos-pkg-install.
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"

cd "$(git rev-parse --show-toplevel)"
REQUIRED="${SEAWORTHY_MACOS_INSTALL_REQUIRED:-0}"
fail() { echo "macos-pkg-install: FAIL: $*" >&2; exit 1; }
ok() { echo "macos-pkg-install: ok    $*"; }
skip() {
    if [ "$REQUIRED" = 1 ]; then fail "$* (SEAWORTHY_MACOS_INSTALL_REQUIRED=1)"; fi
    echo "macos-pkg-install: SKIP  $*"
}

[ "$(uname -s)-$(uname -m)" = "Darwin-arm64" ] || { skip "not an Apple Silicon macOS host"; exit 0; }
sudo -n true 2>/dev/null || { skip "sudo needs a password here"; exit 0; }

FIXTURE=crates/seaworthy-launcher/e2e
TARGET=aarch64-apple-darwin
TARGET_ROOT="${CARGO_TARGET_DIR:-$PWD/target}"
OUT="$TARGET_ROOT/macos-pkg-install"
PACKAGE=acme-agent
BUNDLE_ID=com.example.acme.agent
SERVICE=AcmeAgent
HELPER=AcmeAgent-update
APP="/Applications/Acme Agent.app"
SUPPORT="/Library/Application Support/Acme/Agent"
LOGS="/Library/Logs/Acme/Agent"
TOKEN=1.0.0+conformance
NEXT=1.0.1+conformance
LATER=1.0.2+conformance
FIX=1.0.3+conformance
RC=1.0.0-rc.1+conformance
STAGING="$SUPPORT/updates"
POLICY_VENDOR=/etc/acme
POLICY="$POLICY_VENDOR/agent/policy.toml"

SERVER_PID=
POLICY_MADE=0
PROBLEMS=0
INSTALL_LOG_FROM=$(($(wc -l < /var/log/install.log 2>/dev/null || echo 0) + 1))
# Leaves the VM as it found it, and shows what the daemons and the
# installer wrote.
cleanup() {
    local rc=$?
    if [ "$rc" != 0 ]; then
        for log in "$LOGS/$SERVICE.log" "$LOGS/$HELPER.log"; do
            [ -f "$log" ] && { echo "--- $log"; sudo tail -n 60 "$log"; } >&2
        done
        { echo "--- /var/log/install.log (this run's installs)"; tail -n "+$INSTALL_LOG_FROM" /var/log/install.log | grep -E 'installd|installer\[|PackageKit|postinstall|preinstall|[Aa]cme' | grep -v -i -E 'xprotect|softwareupdated' | tail -n 80; } >&2 || true
    fi
    [ -z "$SERVER_PID" ] || kill "$SERVER_PID" 2>/dev/null || true
    [ ! -x "$APP/Contents/Resources/uninstall" ] || sudo "$APP/Contents/Resources/uninstall" --purge >/dev/null 2>&1 || true
    [ "$POLICY_MADE" = 0 ] || sudo rm -rf "$POLICY_VENDOR"
}
trap cleanup EXIT
# A failed check that lets the lane go on (it shows what followed); the
# lane fails once the step is done.
problem() {
    echo "macos-pkg-install: FAIL: $*" >&2
    PROBLEMS=$((PROBLEMS + 1))
}
note() { echo "macos-pkg-install: note  $*"; }

# Waits up to <seconds> for <command…> to succeed.
await() { # <seconds> <what> <command…>
    local seconds="$1" what="$2"
    shift 2
    local waited=0
    until "$@" >/dev/null 2>&1; do
        [ "$waited" -lt "$seconds" ] || fail "$what (after ${seconds}s)"
        sleep 1
        waited=$((waited + 1))
    done
}
# launchctl print's top-level fields sit one tab deep (BSD sed has no \t).
TAB=$'\t'
receipt() { pkgutil --pkg-info "$BUNDLE_ID" 2>/dev/null | sed -n 's/^version: //p'; }
receipt_is() { [ "$(receipt)" = "$1" ]; }
field() { sudo launchctl print "system/$1" 2>/dev/null | sed -n "s/^${TAB}$2 = //p"; }
state() { field "$1" state; }
pid() { field "$1" pid; }
running() { [ "$(state "$1")" = running ]; }
idle() { [ "$(state "$1")" != running ]; }
loaded() { sudo launchctl print "system/$1" >/dev/null 2>&1; }
# The bundle's version (its Info.plist), as the files on disk say.
bundle_version() { /usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$APP/Contents/Info.plist" 2>/dev/null || true; }

# How many lines of the helper's log say <text>.
said() {
    local n
    n="$(sudo grep -c -F -- "$1" "$LOGS/$HELPER.log" 2>/dev/null || true)"
    echo "${n:-0}"
}
said_more() { [ "$(said "$1")" -gt "$2" ]; }
# Asks for an update as the service does (it runs as root: root writes
# the request file, launchd's WatchPaths starts the helper), waits for the
# helper's log to say <text> once more, then for the run to end.
ask_until() { # <seconds> <text>
    local before
    before="$(said "$2")"
    sudo sh -c "date > '$SUPPORT/state/update-request'; echo $RANDOM >> '$SUPPORT/state/update-request'"
    await "$1" "the helper's log never said: $2" said_more "$2" "$before"
    await 120 "the helper's run didn't end" idle "$HELPER"
}
# Clears the helper's throttle and failure memo, as the time they wait
# would (both live in its staging directory).
reset_helper() { sudo rm -f "$STAGING/last-run" "$STAGING/failure-memo"; }

rm -rf "${OUT:?}"
mkdir -p "$OUT/keys"
[ ! -e "$APP" ] || fail "$APP is already installed: run on a clean machine"
[ ! -e "$POLICY_VENDOR" ] || fail "$POLICY_VENDOR exists: run on a clean machine"

# The tool, a throwaway release key and the product.
CARGO_TARGET_DIR="$TARGET_ROOT" cargo build --quiet --locked -p seaworthy --bin seaworthy
CARGO_TARGET_DIR="$TARGET_ROOT" cargo build --quiet --locked -p seaworthy-updater --example sign_release
TOOL="$TARGET_ROOT/debug/seaworthy"
SIGN="$TARGET_ROOT/debug/examples/sign_release"
"$TOOL" keygen --algorithm ml-dsa-87 --secret "$OUT/keys/release.key" --public "$OUT/keys/release.pub" >/dev/null
printf '[[manifest]]\nalgorithm = "ml-dsa-87"\nkey = "keys/release.key"\n' > "$OUT/signing.toml"
cat > "$OUT/seaworthy.toml" <<'TOML'
[defaults]
vendor = "Acme"
targets = ["x86-64-v3"]
macos-targets = ["apple-m4", "apple-m1"]
channel = "stable"
release-signatures = ["ml-dsa-87"]
release-keys = [{ algorithm = "ml-dsa-87", public-key = "keys/release.pub" }]
maintainer = "Acme Packaging <conformance@example.com>"
license = "MIT OR Apache-2.0"

[product.agent]
display-name = "Acme Agent"
description = "The macOS lane's service."
executable = "demo"
core = "demo_core"
helper = "demo_helper"
windows-directory = "Agent"
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

# Built as the CI template's Mac job builds: the plan, then seaworthy.sh's
# build step; the helper with the seaworthy.toml and the key compiled in
# (its version source and release tree: the lab on loopback, the helper's
# defaults).
WORK="$OUT/work"
mkdir -p "$WORK"
"$TOOL" build-plan --config "$OUT/seaworthy.toml" --triple "$TARGET" --manifest "$FIXTURE/Cargo.toml" \
    > "$WORK/plan-$TARGET.tsv"
SEAWORTHY_WORK="$WORK" SEAWORTHY_MANIFEST="$FIXTURE/Cargo.toml" SEAWORTHY_TARGET_DIR="$OUT/target" \
    SEAWORTHY_VERSION=1.0.0 SEAWORTHY_BUILD_COMMAND="printf %s conformance" \
    SEAWORTHY_LAB_CONFIG="$OUT/seaworthy.toml" SEAWORTHY_LAB_RELEASE_PUB="$OUT/keys/release.pub" \
    bash scripts/ci/seaworthy.sh build "$TARGET" >/dev/null
CARGO_TARGET_DIR="$OUT/target/server" cargo build --quiet --release --locked \
    --manifest-path "$FIXTURE/Cargo.toml" -p conformance_server
SERVER="$OUT/target/server/release/conformance_server"
ok "built the service, its cores, the update helper (the release key compiled in) and the lab server"

# Five releases of the same binaries, signed: 1.0.0-rc.1 (pkg version
# 1.0.0~rc.1-1), 1.0.0, then 1.0.1 to 1.0.3 for the refused, broken and
# recovering updates.
package() { # <version> <sequence>
    "$TOOL" package --config "$OUT/seaworthy.toml" --artifacts "$WORK/artifacts" --out "$OUT/$1" \
        --release "$1" --sequence "$2" --build conformance --signing "$OUT/signing.toml" >/dev/null
    echo "$OUT/$1/agent/packages/$PACKAGE-$1-$2-macos-arm64.pkg"
}
V1="$(package 1.0.0-rc.1 1)"
V2="$(package 1.0.0 2)"
V3="$(package 1.0.1 3)"
V4="$(package 1.0.2 4)"
V5="$(package 1.0.3 5)"
for pkg in "$V1" "$V2" "$V3" "$V4" "$V5"; do
    [ -f "$pkg" ] && [ -f "$pkg.manifest" ] || fail "no $pkg (and its manifest)"
done

# A release manifest for <file>, signed by the lane's release key.
sign() { # <file> <token> <sequence> <format>
    SEAWORTHY_RELEASE_KEY_HEX="$(tr -d '\n' < "$OUT/keys/release.key")" "$SIGN" mldsa87 "$1" \
        --product "$PACKAGE" --version "$2" --sequence "$3" --target "$TARGET" \
        --format "$4" --channel stable >/dev/null
    [ -f "$1.manifest" ] || fail "sign_release wrote no $1.manifest"
}
# <pkg> with one byte mid-file inverted (the same size, another digest).
tamper() { # <pkg> <out>
    cp "$1" "$2"
    local n b
    n=$(($(stat -f %z "$2") / 2))
    b="$(od -An -tu1 -j "$n" -N1 "$2" | tr -d ' ')"
    printf '%b' "\\0$(printf '%03o' $((b ^ 255)))" | dd of="$2" bs=1 seek="$n" conv=notrunc 2>/dev/null
    ! cmp -s "$1" "$2" || fail "tampering with $2 changed nothing"
}
# <pkg> whose component's <script> fails: the postinstall right after its
# umask (before it makes the directories), the preinstall at its end (the
# service stopped). Expanded, the script rewritten (in the Scripts
# directory, or the gzipped cpio archive older pkgutils leave), flattened
# again.
break_pkg() { # <pkg> <out> <preinstall|postinstall>
    local work="$OUT/break" scripts dir
    rm -rf "$work"
    mkdir -p "$work"
    pkgutil --expand "$1" "$work/expanded"
    scripts="$(find "$work/expanded" -name Scripts | head -n 1)"
    [ -n "$scripts" ] || fail "$1 has no Scripts: $(cd "$work/expanded" && find . | head -n 20 | tr '\n' ' ')"
    if [ -d "$scripts" ]; then
        dir="$scripts"
    else
        dir="$work/scripts"
        mkdir -p "$dir"
        (cd "$dir" && gzip -dc "$scripts" | cpio -i --quiet)
    fi
    local program
    case "$3" in
        postinstall) program='{ print } /umask 022/ { print breaks; print "exit 1" }' ;;
        preinstall) program='/^[[:space:]]*exit 0$/ { print breaks; print "exit 1" } { print }' ;;
        *) fail "break_pkg: $3" ;;
    esac
    awk -v breaks="echo \"the lane breaks this $3\" >&2" "$program" "$dir/$3" > "$work/$3"
    grep -q "the lane breaks this $3" "$work/$3" || fail "the $3 has no line to break at"
    cat "$work/$3" > "$dir/$3"
    [ -d "$scripts" ] || (cd "$dir" && find . | cpio -o --format odc --quiet | gzip -c) > "$scripts"
    pkgutil --flatten "$work/expanded" "$2"
}
mkdir -p "$OUT/cases/format" "$OUT/cases/tampered" "$OUT/cases/bad" "$OUT/cases/badpre"
cp "$V3" "$OUT/cases/format/$PACKAGE.pkg"
sign "$OUT/cases/format/$PACKAGE.pkg" "$NEXT" 3 zip
tamper "$V3" "$OUT/cases/tampered/$PACKAGE.pkg"
cp "$V3.manifest" "$OUT/cases/tampered/$PACKAGE.pkg.manifest"
BAD="$OUT/cases/bad/$PACKAGE.pkg"
break_pkg "$V3" "$BAD" postinstall
sign "$BAD" "$NEXT" 3 pkg
BADPRE="$OUT/cases/badpre/$PACKAGE.pkg"
break_pkg "$V4" "$BADPRE" preinstall
sign "$BADPRE" "$LATER" 4 pkg

# The helper's release tree: <product>/<channel>/<token>/<target>/<product>.<format>.
stage() { # <token> <pkg> <manifest>
    local dir="$OUT/www/repo/releases/$PACKAGE/stable/$1/$TARGET"
    rm -rf "$dir"
    mkdir -p "$dir"
    cp "$2" "$dir/$PACKAGE.pkg"
    cp "$3" "$dir/$PACKAGE.pkg.manifest"
}
# The lab names one token: restarted to name another.
serve() { # <token>
    if [ -n "$SERVER_PID" ]; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -f "$OUT/ready"
    "$SERVER" --root "$OUT/www" --token "$1" --ready "$OUT/ready" &
    SERVER_PID=$!
    await 30 "the lab didn't start naming $1" test -f "$OUT/ready"
}
stage "$TOKEN" "$V2" "$V2.manifest"
serve "$TOKEN"
ok "packaged 1.0.0-rc.1 to 1.0.3 with signed manifests, and the refused and broken cases; the lab answers $TOKEN"

# 1. Installed by hand.
sudo installer -pkg "$V1" -target / >/dev/null || fail "installer -pkg $V1 failed"
[ "$(receipt)" = "1.0.0~rc.1-1" ] || fail "the receipt names $(receipt)"
await 30 "the service isn't running: $(state "$SERVICE")" running "$SERVICE"
sudo launchctl print "system/$HELPER" >/dev/null 2>&1 || fail "the helper's daemon isn't loaded"
[ "$(state "$HELPER")" != running ] || fail "the helper runs unasked"
await 30 "the service logged no core" sudo grep -q "core=apple-m1" "$LOGS/$SERVICE.log"
for dir in "$SUPPORT/state" "$SUPPORT/updates"; do
    [ "$(sudo stat -f '%Su %Lp' "$dir")" = "root 700" ] || fail "$dir: $(sudo stat -f '%Su %Lp' "$dir")"
done
codesign --verify --deep --strict "$APP" || fail "the installed bundle doesn't verify"
FIRST="$(pid "$SERVICE")"
ok "installed 1.0.0-rc.1: launchd runs the service (pid $FIRST), the helper's daemon waits"

# 2. The update helper, asked through its request file.
sudo sh -c "date > '$SUPPORT/state/update-request'"
await 300 "the helper didn't install 1.0.0: the receipt names $(receipt)" receipt_is 1.0.0-2
await 60 "the helper's log doesn't say it installed 1.0.0" \
    sudo grep -q "installed $PACKAGE 1.0.0 (sequence 2)" "$LOGS/$HELPER.log"
await 60 "the service isn't running after the update: $(state "$SERVICE")" running "$SERVICE"
SECOND="$(pid "$SERVICE")"
[ -n "$SECOND" ] && [ "$SECOND" != "$FIRST" ] || fail "the service wasn't restarted (pid $FIRST, then $SECOND)"
sudo launchctl print "system/$HELPER" >/dev/null 2>&1 || fail "the helper's daemon is gone after the update"
ok "the helper installed 1.0.0 (the receipt, its log); the service restarted (pid $SECOND)"

# 3. Refused releases never reach the installer.
refused() { # <case> <text>
    reset_helper
    ask_until 180 "$2"
    receipt_is 1.0.0-2 || fail "$1: the receipt names $(receipt)"
    [ "$(pid "$SERVICE")" = "$SECOND" ] || fail "$1: the service was stopped or restarted (pid $SECOND, now $(pid "$SERVICE"))"
    ok "$1: refused ($2); 1.0.0 stays, the service untouched"
}
serve "$NEXT"
stage "$NEXT" "$OUT/cases/format/$PACKAGE.pkg" "$OUT/cases/format/$PACKAGE.pkg.manifest"
refused "a manifest for another format" "release manifest format mismatch"
stage "$NEXT" "$OUT/cases/tampered/$PACKAGE.pkg" "$OUT/cases/tampered/$PACKAGE.pkg.manifest"
refused "a tampered pkg under its valid manifest" "digest mismatch"
serve "$RC"
stage "$RC" "$V1" "$V1.manifest"
refused "a downgrade to 1.0.0-rc.1" "refusing to downgrade"

# 4. The administrator's policy file.
serve "$NEXT"
stage "$NEXT" "$V3" "$V3.manifest"
POLICY_MADE=1
sudo mkdir -p "$(dirname "$POLICY")"
sudo sh -c "printf 'updates = \"off\"\\n' > '$POLICY'"
sudo chmod 0644 "$POLICY"
# shellcheck disable=SC2016 # the backticks are the helper's log text
refused "the policy file's off" 'update policy is `off` from'
sudo sh -c "printf 'updates = \"auto\"\\n' > '$POLICY'"
sudo chmod 0666 "$POLICY"
refused "a policy file others can write (auto)" "an untrusted or invalid source"
sudo rm -rf "$POLICY_VENDOR"
POLICY_MADE=0

# 5. Failed updates.
# Waits up to a minute for the service; a problem if it doesn't run.
service_runs() { # <when>
    local waited=0
    until running "$SERVICE" || [ "$waited" -ge 60 ]; do
        sleep 1
        waited=$((waited + 1))
    done
    if running "$SERVICE"; then
        ok "the service runs $1 (pid $(pid "$SERVICE"))"
    else
        problem "the service isn't running $1: '$(state "$SERVICE")'"
    fi
}
observed() { # <when>
    note "$1: the receipt names $(receipt); the bundle's version is $(bundle_version); the service is '$(state "$SERVICE")' (pid $(pid "$SERVICE")); the helper's daemon is $(loaded "$HELPER" && echo loaded || echo unloaded)"
}
# 1.0.1's postinstall fails.
stage "$NEXT" "$BAD" "$BAD.manifest"
reset_helper
ask_until 300 "installer -pkg failed"
observed "after the failed postinstall"
# A request right after backs off: the throttle cleared, the failure
# memo kept (its first window is a minute from the attempt).
FAILED="$(said "installer -pkg failed")"
sudo rm -f "$STAGING/last-run"
ask_until 45 "updating to $NEXT failed recently"
if [ "$(said "installer -pkg failed")" = "$FAILED" ]; then
    ok "a request right after backs off: the helper didn't run the installer again"
else
    problem "the helper ran the installer again instead of backing off"
fi
service_runs "after the failed postinstall"
loaded "$HELPER" || problem "the helper's daemon is gone after the failed postinstall"
# 1.0.2's preinstall fails once it has stopped the service: no
# postinstall runs, the helper starts the service again.
serve "$LATER"
stage "$LATER" "$BADPRE" "$BADPRE.manifest"
reset_helper
ask_until 300 "installer -pkg failed"
observed "after the failed preinstall"
service_runs "after the failed preinstall"
[ "$(said "left $SERVICE unloaded: started it again")" -gt 0 ] ||
    problem "the helper's log doesn't say it started $SERVICE again"
loaded "$HELPER" || problem "the helper's daemon is gone after the failed preinstall"
# 1.0.3 installs over them.
serve "$FIX"
stage "$FIX" "$V5" "$V5.manifest"
reset_helper
ask_until 300 "installed $PACKAGE 1.0.3 (sequence 5)"
receipt_is 1.0.3-5 || problem "after 1.0.3's install the receipt names $(receipt)"
service_runs "after the helper rolled forward to 1.0.3 (the receipt names $(receipt))"
[ "$PROBLEMS" = 0 ] || fail "$PROBLEMS check(s) failed above"

# 6. Removed.
sudo "$APP/Contents/Resources/uninstall" --purge >/dev/null || fail "the uninstaller failed"
for label in "$SERVICE" "$HELPER"; do
    ! sudo launchctl print "system/$label" >/dev/null 2>&1 || fail "$label is still loaded"
    [ ! -e "/Library/LaunchDaemons/$label.plist" ] || fail "$label.plist is still there"
done
[ ! -e "$APP" ] || fail "$APP is still there"
! pkgutil --pkg-info "$BUNDLE_ID" >/dev/null 2>&1 || fail "the receipt is still there"
[ ! -e "$SUPPORT" ] && [ ! -e "$LOGS" ] || fail "--purge left the state or the logs"
ok "the uninstaller removed the daemons, the app, the receipt, the state and the logs"

echo "macos-pkg-install: all checks passed"
