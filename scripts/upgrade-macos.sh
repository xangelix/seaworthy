#!/usr/bin/env bash
# scripts/upgrade-macos.sh — the upgrade-from-previous lane on macOS: the
# lab fixture's PREVIOUS build (scripts/upgrade-previous.sh) installed on
# this Mac, then updated to this checkout's build (scripts/
# upgrade-candidate.sh macos) by its own update helper, against the lab:
#
#   1. the lab: a throwaway CA (name-constrained to the lab's names, its key
#      never written) trusted in the System keychain, its leaf for
#      packages.lab.invalid and updates.lab.invalid (the names the helper
#      is built to dial), both mapped to the loopback in /etc/hosts; the lab
#      server on 443 (IPv4 and IPv6) answers the candidate's version token
#      at the required-version endpoint and serves the release tree; the
#      lab's client, the helper's own TLS construction, reads the token
#      through the System keychain before anything is installed;
#   2. the previous build: its pkg installed with `installer`; the receipt
#      names it, launchd runs the service and has the helper's daemon
#      loaded;
#   3. policy honored: the administrator's policy file says `off`; the
#      service's request (the file the helper's daemon watches, which the
#      root service writes) installs nothing;
#   4. another key refused: the candidate's manifest re-signed by a
#      throwaway key; the helper refuses it and installs nothing;
#   5. the update: after the helper's backoff (at least 70 s), the real
#      manifest; the helper verifies and installs the candidate;
#   6. the transition: the receipt names the candidate, the helper's log
#      says it installed it, the service runs again under a new process,
#      the installed files are the candidate's (lab/build.txt names its
#      token), the helper's daemon stays loaded, the service's state
#      survived;
#   7. the bundle's uninstaller (--purge) leaves nothing.
#
#   scripts/upgrade-macos.sh <previous> <candidate>
#
# Apple Silicon with passwordless sudo only (a GitHub-hosted macOS runner, a
# throwaway VM: it installs system daemons and edits /etc/hosts and the
# System keychain, and restores them on every exit path). Elsewhere it
# SKIPs, or fails with SEAWORTHY_UPGRADE_REQUIRED=1. Needs bash 4.4+,
# python3 and rustup with rust-toolchain.toml's toolchain (it builds the lab
# binary). Evidence (the daemons' logs, the lab server's) lands in
# ${CARGO_TARGET_DIR:-target}/lab-upgrade-macos/evidence.
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"

cd "$(git rev-parse --show-toplevel)"
REQUIRED="${SEAWORTHY_UPGRADE_REQUIRED:-0}"
fail() { echo "upgrade-macos: FAIL: $*" >&2; exit 1; }
ok() { echo "upgrade-macos: ok    $*"; }
say() { echo "upgrade-macos: $*"; }
skip() {
    if [ "$REQUIRED" = 1 ]; then fail "$* (SEAWORTHY_UPGRADE_REQUIRED=1)"; fi
    echo "upgrade-macos: SKIP  $*"
    exit 0
}

previous="${1:-}"
candidate="${2:-}"
[ -n "$previous" ] && [ -n "$candidate" ] || { echo "usage: $0 <previous> <candidate>" >&2; exit 2; }
[ "$(uname -s)-$(uname -m)" = "Darwin-arm64" ] || skip "not an Apple Silicon macOS host"
sudo -n true 2>/dev/null || skip "sudo needs a password here"

TARGET_ROOT="${CARGO_TARGET_DIR:-$PWD/target}"
OUT="$TARGET_ROOT/lab-upgrade-macos"
EVIDENCE="$OUT/evidence"
LAB="$OUT/lab"
WWW="$OUT/www"
PACKAGE=acme-daemon
BUNDLE_ID=com.example.acme.daemon
SERVICE=AcmeDaemon
HELPER=AcmeDaemon-update
APP="/Applications/Acme Daemon.app"
SUPPORT="/Library/Application Support/Acme/Daemon"
STATE="$SUPPORT/state"
LOGS=/Library/Logs/Acme/Daemon
POLICY_VENDOR=/etc/acme
POLICY="$POLICY_VENDOR/daemon/policy.toml"
TRIPLE=aarch64-apple-darwin
PACKAGES_HOST=packages.lab.invalid
UPDATES_HOST=updates.lab.invalid
HOSTS_MARK="# seaworthy lab"
REFUSED="no trusted release key verified it"
# shellcheck disable=SC2016 # the backticks are the helper's log text
POLICY_OFF='update policy is `off` from'
BACKOFF=70

# --- the builds ----------------------------------------------------------------

field() { # <json file> <field>
    python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])' "$1" "$2"
}
pkg_of() { # <build dir>: its one pkg
    python3 -I -c '
import json, sys
files = [a["file"] for a in json.load(open(sys.argv[1] + "/packages.json"))["artifacts"] if a["kind"] == "pkg"]
if len(files) != 1:
    sys.exit("expected one pkg, found %d" % len(files))
print(sys.argv[1] + "/" + files[0])' "$1"
}
# The receipt's spelling of a release: the version with "~" for its first
# "-", then "-<sequence>".
receipt_of() { # <build dir>
    local version sequence
    version="$(field "$1/lab-build.json" version)"
    sequence="$(field "$1/lab-build.json" sequence)"
    echo "${version/-/\~}-$sequence"
}
for dir in "$previous" "$candidate"; do
    [ -f "$dir/lab-build.json" ] || fail "$dir has no lab-build.json"
    [ "$(field "$dir/lab-build.json" platform)" = macos ] || fail "$dir isn't a macOS build"
    [ "$(field "$dir/lab-build.json" package)" = "$PACKAGE" ] || fail "$dir isn't $PACKAGE"
    grep -q '"ci_test": true' "$dir/packages.json" || fail "$dir isn't signed with the CI test key"
done
[ "$(field "$previous/lab-build.json" trust)" = "$(field "$candidate/lab-build.json" trust)" ] ||
    fail "the previous build trusts another CI test key (scripts/upgrade-previous.sh skips such a build)"
PREV_PKG="$(pkg_of "$previous")"
CAND_PKG="$(pkg_of "$candidate")"
PREV_RECEIPT="$(receipt_of "$previous")"
CAND_RECEIPT="$(receipt_of "$candidate")"
CAND_TOKEN="$(field "$candidate/lab-build.json" token)"
CAND_VERSION="$(field "$candidate/lab-build.json" version)"
CAND_SEQUENCE="$(field "$candidate/lab-build.json" sequence)"
[ "$(field "$previous/lab-build.json" sequence)" -lt "$CAND_SEQUENCE" ] ||
    fail "the previous build ($PREV_RECEIPT) isn't older than the candidate ($CAND_RECEIPT)"
[ -f "$CAND_PKG.manifest" ] || fail "the candidate $CAND_PKG has no manifest"
ok "the previous build $PREV_RECEIPT, the candidate $CAND_RECEIPT ($CAND_TOKEN)"

# --- helpers -------------------------------------------------------------------

await() { # <seconds> <what> <command…>
    local seconds="$1" what="$2" waited=0
    shift 2
    until "$@" >/dev/null 2>&1; do
        [ "$waited" -lt "$seconds" ] || fail "$what (after ${seconds}s)"
        sleep 1
        waited=$((waited + 1))
    done
}
TAB=$'\t'
receipt() { pkgutil --pkg-info "$BUNDLE_ID" 2>/dev/null | sed -n 's/^version: //p'; }
receipt_is() { [ "$(receipt)" = "$1" ]; }
launchd_field() { sudo launchctl print "system/$1" 2>/dev/null | sed -n "s/^${TAB}$2 = //p"; }
running() { [ "$(launchd_field "$1" state)" = running ]; }
idle() { [ "$(launchd_field "$1" state)" != running ]; }
pid_of() { launchd_field "$1" pid; }
loaded() { sudo launchctl print "system/$1" >/dev/null 2>&1; }
said() { # how many lines of the helper's log say <text>
    local n
    n="$(sudo grep -c -F -- "$1" "$LOGS/$HELPER.log" 2>/dev/null || true)"
    echo "${n:-0}"
}
said_more() { [ "$(said "$1")" -gt "$2" ]; }
# Asks for an update as the root service does (it writes the request file;
# launchd's WatchPaths starts the helper), waits for the helper's log to
# say <text> once more, then for the run to end.
ask_until() { # <seconds> <text>
    local before
    before="$(said "$2")"
    sudo sh -c "date > '$STATE/update-request'; echo $RANDOM >> '$STATE/update-request'"
    await "$1" "the helper's log never said: $2" said_more "$2" "$before"
    await 120 "the helper's run didn't end" idle "$HELPER"
}
untouched() { # <case> <pid>
    receipt_is "$PREV_RECEIPT" || fail "$1: the receipt names $(receipt)"
    [ "$(pid_of "$SERVICE")" = "$2" ] || fail "$1: the service was stopped or restarted (pid $2, now $(pid_of "$SERVICE"))"
}

# --- cleanup: the VM as it was ---------------------------------------------------

SERVER_PID=""
POLICY_MADE=0
cleanup() {
    local rc=$?
    mkdir -p "$EVIDENCE"
    for log in "$LOGS/$SERVICE.log" "$LOGS/$HELPER.log"; do
        if sudo test -f "$log"; then
            sudo cp "$log" "$EVIDENCE/" 2>/dev/null || true
            [ "$rc" = 0 ] || { echo "--- $log (last 60 lines)" >&2; sudo tail -n 60 "$log" >&2; }
        fi
    done
    [ -z "$SERVER_PID" ] || sudo kill "$SERVER_PID" 2>/dev/null || true
    sudo chown -R "$(id -u)" "$EVIDENCE" 2>/dev/null || true
    [ ! -x "$APP/Contents/Resources/uninstall" ] || sudo "$APP/Contents/Resources/uninstall" --purge >/dev/null 2>&1 || true
    [ "$POLICY_MADE" = 0 ] || sudo rm -rf "$POLICY_VENDOR"
    if grep -q "$HOSTS_MARK" /etc/hosts 2>/dev/null; then
        sudo sed -i '' "/$HOSTS_MARK/d" /etc/hosts
        sudo dscacheutil -flushcache 2>/dev/null || true
        sudo killall -HUP mDNSResponder 2>/dev/null || true
    fi
    if [ -f "$LAB/tls/ca.pem" ]; then
        sudo security remove-trusted-cert -d "$LAB/tls/ca.pem" 2>/dev/null || true
        sudo security delete-certificate -Z "$(openssl x509 -in "$LAB/tls/ca.pem" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d :)" \
            /Library/Keychains/System.keychain 2>/dev/null || true
    fi
    if [ -s "$LAB/authdb.plist" ]; then
        # The right as the lane saved it (its own file).
        # shellcheck disable=SC2024
        sudo security authorizationdb write com.apple.trust-settings.admin < "$LAB/authdb.plist" >/dev/null 2>&1 || true
    fi
    exit "$rc"
}
trap cleanup EXIT

[ ! -e "$APP" ] || fail "$APP is already installed: run on a clean machine"
! pkgutil --pkg-info "$BUNDLE_ID" >/dev/null 2>&1 || fail "the receipt $BUNDLE_ID already exists: run on a clean machine"
[ ! -e "$POLICY_VENDOR" ] || fail "$POLICY_VENDOR exists: run on a clean machine"
rm -rf "${OUT:?}"
mkdir -p "$EVIDENCE" "$LAB" "$WWW"

# --- 1. the lab ------------------------------------------------------------------

CARGO_TARGET_DIR="$TARGET_ROOT" cargo build --quiet --locked -p seaworthy-lab --bin seaworthy-lab
LABBIN="$TARGET_ROOT/debug/seaworthy-lab"
"$LABBIN" ca --out "$LAB/tls" --name "$PACKAGES_HOST" --name "$UPDATES_HOST" >/dev/null
# Admin trust settings may need an authorization macOS asks a person for:
# then, in the throwaway VM, the right is opened for the lane and restored
# after.
trust_ca() { sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$LAB/tls/ca.pem"; }
if ! trust_ca 2> "$LAB/trust.err"; then
    say "the System keychain refused the lab CA: $(tr '\n' ' ' < "$LAB/trust.err")"
    say "opening com.apple.trust-settings.admin for the lane"
    # shellcheck disable=SC2024 # the copy is the lane's own file
    sudo security authorizationdb read com.apple.trust-settings.admin > "$LAB/authdb.plist" ||
        say "reading the right failed (exit $?)"
    sudo security authorizationdb write com.apple.trust-settings.admin allow ||
        fail "opening com.apple.trust-settings.admin failed"
    trust_ca || fail "the System keychain refused the lab CA with the right open"
fi
for host in "$PACKAGES_HOST" "$UPDATES_HOST"; do
    security verify-cert -c "$LAB/tls/leaf.pem" -p ssl -s "$host" -k /Library/Keychains/System.keychain >/dev/null ||
        fail "macOS doesn't trust the lab leaf for $host (security verify-cert)"
done
ok "the System keychain trusts the lab CA (constrained to $PACKAGES_HOST and $UPDATES_HOST)"

printf '127.0.0.1 %s %s %s\n::1 %s %s %s\n' "$PACKAGES_HOST" "$UPDATES_HOST" "$HOSTS_MARK" \
    "$PACKAGES_HOST" "$UPDATES_HOST" "$HOSTS_MARK" | sudo tee -a /etc/hosts >/dev/null
sudo dscacheutil -flushcache
sudo killall -HUP mDNSResponder 2>/dev/null || true
await 30 "$PACKAGES_HOST doesn't resolve to the loopback" \
    sh -c "dscacheutil -q host -a name $PACKAGES_HOST | grep -q '127.0.0.1'"

# The release tree, as the helper's URL template names it.
RELEASE="$WWW/repo/releases/$PACKAGE/stable/$CAND_TOKEN/$TRIPLE"
mkdir -p "$RELEASE"
cp "$CAND_PKG" "$RELEASE/$PACKAGE.pkg"
"$LABBIN" foreign-manifest --manifest "$CAND_PKG.manifest" --out "$LAB/foreign.manifest"
printf '%s\n' "$CAND_TOKEN" > "$LAB/token"
# The log is the lane's own file (written by this shell, not by sudo).
# shellcheck disable=SC2024
sudo "$LABBIN" serve --root "$WWW" --token-file "$LAB/token" --ready "$LAB/ready" \
    --listen 127.0.0.1:443 --listen '[::1]:443' \
    --tls-cert "$LAB/tls/leaf.pem" --tls-key "$LAB/tls/leaf.key" > "$EVIDENCE/lab-server.log" 2>&1 &
SERVER_PID=$!
await 30 "the lab server didn't start" test -f "$LAB/ready"
# Through the helper's own TLS construction (seaworthy-crypto's policy, the
# System keychain), as root, as the helper runs.
answered="$(sudo "$LABBIN" required-version --url "https://$UPDATES_HOST/_lab/required-version")" ||
    fail "the lab's client can't read the required version through the System keychain"
[ "$answered" = "$CAND_TOKEN" ] || fail "the lab answered $answered, not $CAND_TOKEN"
ok "the lab answers $CAND_TOKEN at https://$UPDATES_HOST and serves the release tree at https://$PACKAGES_HOST"

# --- 2. the previous build -------------------------------------------------------

sudo installer -pkg "$PREV_PKG" -target / >/dev/null || fail "installer -pkg $PREV_PKG failed"
receipt_is "$PREV_RECEIPT" || fail "the receipt names $(receipt), not $PREV_RECEIPT"
await 30 "the service isn't running: $(launchd_field "$SERVICE" state)" running "$SERVICE"
await 30 "the helper's daemon isn't loaded" loaded "$HELPER"
idle "$HELPER" || fail "the helper runs unasked"
await 30 "the service logged no core" sudo grep -q "core=apple-m1" "$LOGS/$SERVICE.log"
sudo sh -c "echo kept > '$STATE/lab-state'"
FIRST_PID="$(pid_of "$SERVICE")"
ok "installed the previous build: the receipt names $PREV_RECEIPT, launchd runs the service (pid $FIRST_PID)"

# --- 3. the administrator's policy says off ---------------------------------------

POLICY_MADE=1
sudo mkdir -p "$(dirname "$POLICY")"
sudo sh -c "printf 'updates = \"off\"\\n' > '$POLICY'"
sudo chmod 0644 "$POLICY"
cp "$CAND_PKG.manifest" "$RELEASE/$PACKAGE.pkg.manifest"
ask_until 180 "$POLICY_OFF"
untouched "the policy's off" "$FIRST_PID"
sudo rm -rf "$POLICY_VENDOR"
POLICY_MADE=0
ok "the administrator's \`off\` policy: the helper installed nothing"

# --- 4. another key: refused -------------------------------------------------------

cp "$LAB/foreign.manifest" "$RELEASE/$PACKAGE.pkg.manifest"
ask_until 300 "$REFUSED"
untouched "another key" "$FIRST_PID"
ok "the helper refused the manifest another key signed; the receipt still names $PREV_RECEIPT"

# --- 5. the update ---------------------------------------------------------------

# The helper throttles a run within 30 s of the last, and backs off a
# minute after a failed release.
sleep "$BACKOFF"
cp "$CAND_PKG.manifest" "$RELEASE/$PACKAGE.pkg.manifest"
sudo sh -c "date > '$STATE/update-request'"
await 600 "the helper didn't install the candidate: the receipt names $(receipt)" receipt_is "$CAND_RECEIPT"
await 60 "the helper's log doesn't say it installed the candidate" \
    sudo grep -q -F "installed $PACKAGE $CAND_VERSION (sequence $CAND_SEQUENCE)" "$LOGS/$HELPER.log"

# --- 6. the transition -------------------------------------------------------------

await 120 "the service isn't running after the update: $(launchd_field "$SERVICE" state)" running "$SERVICE"
SECOND_PID="$(pid_of "$SERVICE")"
[ -n "$SECOND_PID" ] && [ "$SECOND_PID" != "$FIRST_PID" ] ||
    fail "the service wasn't restarted (pid $FIRST_PID, then $SECOND_PID)"
loaded "$HELPER" || fail "the helper's daemon is gone after the update"
[ "$(cat "$APP/Contents/Resources/lab/build.txt")" = "$CAND_TOKEN" ] ||
    fail "the installed files aren't the candidate's: lab/build.txt names $(cat "$APP/Contents/Resources/lab/build.txt")"
[ "$(sudo cat "$STATE/lab-state")" = kept ] || fail "the service's state didn't survive the update"
codesign --verify --deep --strict "$APP" || fail "the updated bundle doesn't verify"
ok "the helper installed $CAND_RECEIPT; the service runs again (pid $SECOND_PID), its files are the candidate's, its state kept"

# --- 7. removed ------------------------------------------------------------------

# The helper's run outlives the receipt and the service's restart (it logs,
# records the release, exits). The uninstaller waits for the daemons itself,
# but the lane checks removal of a quiet product.
await 120 "the helper is still running after the update: $(launchd_field "$HELPER" state)" idle "$HELPER"
sudo "$APP/Contents/Resources/uninstall" --purge >/dev/null || fail "the uninstaller failed"
for label in "$SERVICE" "$HELPER"; do
    ! loaded "$label" || fail "$label is still loaded"
    [ ! -e "/Library/LaunchDaemons/$label.plist" ] || fail "$label.plist is still there"
done
[ ! -e "$APP" ] || fail "$APP is still there"
! pkgutil --pkg-info "$BUNDLE_ID" >/dev/null 2>&1 || fail "the receipt is still there"
[ ! -e "$SUPPORT" ] && [ ! -e "$LOGS" ] || fail "--purge left the state or the logs"
ok "the uninstaller removed the daemons, the app, the receipt, the state and the logs"
echo "upgrade-macos: the previous build ($PREV_RECEIPT) updated to the candidate ($CAND_RECEIPT)"
