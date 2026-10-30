#!/usr/bin/env bash
# scripts/ci/apple-keychain.sh — a Developer ID keychain made for one command,
# from credentials a secret store handed over in the environment. A signing
# step on macOS runs under it:
#
#   apple-keychain.sh <signing.toml> -- <seaworthy> package …
#
# 1. the identities' PKCS#12 and the notary service's API key (below) become
#    a keychain of its own in a private directory (a random password, locked
#    after two hours: the step's longest run, notarization included), first
#    in the search list, with the API key stored in it as a notarytool
#    profile. Those steps run with the system's basics alone in their
#    environment: no other credential the step holds reaches `security`,
#    `openssl` or `notarytool`;
# 2. the credentials leave the environment;
# 3. the command runs with `--signing <a copy of signing.toml with [apple]>`
#    appended: the identities the keychain holds, the keychain and the
#    profile. Names and paths only: the copy sits beside the original, so
#    what the original names relative to itself still resolves. Whose
#    signatures count stays seaworthy.toml's `[defaults.apple]`;
# 4. however the command ends (or the step is interrupted), the keychain is
#    deleted and the directory shredded.
#
# Environment:
#
#   SEAWORTHY_APPLE_P12            the Developer ID Application identity (and,
#                                  for a pkg, the Developer ID Installer
#                                  identity) with their private keys: one
#                                  PKCS#12, base64
#   SEAWORTHY_APPLE_P12_PASSWORD   its password
#   SEAWORTHY_APPLE_NOTARY_KEY     an App Store Connect API key: the .p8 file's
#                                  text, or that text in base64
#   SEAWORTHY_APPLE_NOTARY_KEY_ID  its key id
#   SEAWORTHY_APPLE_NOTARY_ISSUER  its issuer id
#   SEAWORTHY_APPLE_IDENTITY       optional: the Developer ID Application
#                                  identity to sign with, when the PKCS#12
#                                  holds several (default: the first)
#
# seaworthy.sh package-macos runs it, under the step's secrets prefix, on a
# release with SEAWORTHY_MACOS_SIGN=1 whose signing configuration has no
# [apple] of its own. The GitHub workflow's github.sh sources this file for
# apple_keychain alone.
#
# Secrets go to files only under the private directory (umask 077), and never
# onto a command line. The PKCS#12's password reaches openssl alone, through
# its environment: each identity is re-wrapped under a throwaway password,
# which is what `security import` (which takes one only as -P, on its command
# line) sees; the keychain's own password is random, used for this run alone,
# and deleted with the keychain. Bash 3.2 runs the functions: macOS's
# /bin/bash, on GitHub's runners before their step that installs a later one.

# OpenSSL proper: macOS's /usr/bin/openssl is LibreSSL, which can't open the
# PKCS#12 files OpenSSL 3 writes, so Homebrew's OpenSSL 3 comes first.
apple_openssl() {
    local brew
    for brew in /opt/homebrew/opt/openssl@3/bin/openssl /usr/local/opt/openssl@3/bin/openssl; do
        if [ -x "$brew" ]; then
            "$brew" "$@"
            return
        fi
    done
    openssl "$@"
}

# Overwrites and removes files (GNU shred where there is one; macOS's
# filesystems give no such guarantee, so there they're only removed).
apple_shred() { # <file>...
    local file
    for file in "$@"; do
        [ -f "$file" ] || continue
        if command -v shred >/dev/null 2>&1; then
            shred -u -z -- "$file" 2>/dev/null || rm -f -- "$file"
        else
            rm -f -- "$file"
        fi
    done
}

# The Developer ID identities imported into a keychain of their own in <dir>,
# first in the search list, and the notary service's API key stored as a
# notarytool profile in it. Sets apple_identity, apple_installer,
# apple_keychain_path and apple_profile.
apple_keychain() { # <dir>
    [ "$(uname -s)" = Darwin ] || fail "the Developer ID keychain is made on macOS"
    [ -n "${SEAWORTHY_APPLE_P12:-}" ] || fail "no Developer ID PKCS#12 (SEAWORTHY_APPLE_P12, the workflow's APPLE_CERTIFICATE_P12 secret)"
    local variable
    for variable in SEAWORTHY_APPLE_NOTARY_KEY SEAWORTHY_APPLE_NOTARY_KEY_ID SEAWORTHY_APPLE_NOTARY_ISSUER; do
        [ -n "${!variable:-}" ] || fail "Developer ID signing notarizes: the App Store Connect API key is required (SEAWORTHY_APPLE_NOTARY_KEY, _KEY_ID and _ISSUER; the workflow's APPLE_NOTARY_KEY, APPLE_NOTARY_KEY_ID and APPLE_NOTARY_ISSUER secrets)"
    done
    [[ "$SEAWORTHY_APPLE_NOTARY_KEY_ID" =~ ^[A-Z0-9]{6,20}$ ]] || fail "the notary key id (SEAWORTHY_APPLE_NOTARY_KEY_ID) isn't an App Store Connect key id"
    [[ "$SEAWORTHY_APPLE_NOTARY_ISSUER" =~ ^[0-9a-fA-F-]{36}$ ]] || fail "the notary issuer (SEAWORTHY_APPLE_NOTARY_ISSUER) isn't an issuer id (a UUID)"
    local temp="$1/apple"
    umask 077
    mkdir -p "$temp"
    local keychain="$1/signing.keychain-db" password profile=seaworthy-notary throwaway
    password="$(apple_openssl rand -hex 24)"
    throwaway="$(apple_openssl rand -hex 24)"
    # Only GitHub's log masks a value; elsewhere neither is ever printed.
    if [ "${GITHUB_ACTIONS:-}" = true ]; then
        echo "::add-mask::$password"
        echo "::add-mask::$throwaway"
    fi
    security create-keychain -p "$password" "$keychain"
    security set-keychain-settings -lut 7200 "$keychain"
    security unlock-keychain -p "$password" "$keychain"
    base64 -d > "$temp/identity.p12" <<<"$SEAWORTHY_APPLE_P12" || fail "the Developer ID PKCS#12 isn't base64"
    local legacy=()
    SEAWORTHY_P12_IN="${SEAWORTHY_APPLE_P12_PASSWORD:-}" \
        apple_openssl pkcs12 -in "$temp/identity.p12" -passin env:SEAWORTHY_P12_IN -noout 2>/dev/null ||
        legacy=(-legacy)
    # ${legacy[@]+…}: on bash 3.2 an empty array trips set -u.
    SEAWORTHY_P12_IN="${SEAWORTHY_APPLE_P12_PASSWORD:-}" \
        apple_openssl pkcs12 ${legacy[@]+"${legacy[@]}"} -in "$temp/identity.p12" -passin env:SEAWORTHY_P12_IN \
        -nokeys -out "$temp/certificates.pem" 2>/dev/null ||
        fail "the Developer ID PKCS#12 doesn't open with its password"
    # Each private key into a file of its own (the Application and the
    # Installer identities share one PKCS#12).
    SEAWORTHY_P12_IN="${SEAWORTHY_APPLE_P12_PASSWORD:-}" \
        apple_openssl pkcs12 ${legacy[@]+"${legacy[@]}"} -in "$temp/identity.p12" -passin env:SEAWORTHY_P12_IN \
        -nocerts -nodes 2>/dev/null |
        awk -v dir="$temp" '/^-----BEGIN [A-Z ]*PRIVATE KEY-----$/ { n++; file = dir "/key-" n ".pem" }
            file { print > file }
            /^-----END [A-Z ]*PRIVATE KEY-----$/ { close(file); file = "" }' ||
        fail "the Developer ID PKCS#12's keys don't open with its password"
    rm -f "$temp/identity.p12"
    local keys=("$temp"/key-*.pem) key
    [ -f "${keys[0]}" ] || fail "the Developer ID PKCS#12 holds no private key"
    for key in "${keys[@]}"; do
        # The certificate matching the key leads; the others ride along.
        SEAWORTHY_P12_OUT="$throwaway" apple_openssl pkcs12 -export -inkey "$key" -in "$temp/certificates.pem" \
            -passout env:SEAWORTHY_P12_OUT -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1 \
            -out "$key.p12" 2>/dev/null || fail "a key in the Developer ID PKCS#12 has no certificate"
        apple_shred "$key"
        security import "$key.p12" -k "$keychain" -f pkcs12 -P "$throwaway" \
            -T /usr/bin/codesign -T /usr/bin/productbuild >/dev/null ||
            fail "an identity in the Developer ID PKCS#12 doesn't import into the keychain"
        apple_shred "$key.p12"
    done
    apple_shred "$temp/certificates.pem"
    security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$password" "$keychain" >/dev/null
    # This keychain first, the user's others after it.
    local existing=() line
    while IFS= read -r line; do
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line#\"}"
        line="${line%\"}"
        [ -n "$line" ] && existing+=("$line")
    done < <(security list-keychains -d user)
    security list-keychains -d user -s "$keychain" ${existing[@]+"${existing[@]}"}
    if [[ "$SEAWORTHY_APPLE_NOTARY_KEY" == -----BEGIN* ]]; then
        printf '%s\n' "$SEAWORTHY_APPLE_NOTARY_KEY" > "$temp/AuthKey.p8"
    else
        base64 -d > "$temp/AuthKey.p8" <<<"$SEAWORTHY_APPLE_NOTARY_KEY" || fail "the notary key is neither a .p8 key nor base64"
    fi
    xcrun notarytool store-credentials "$profile" --key "$temp/AuthKey.p8" \
        --key-id "$SEAWORTHY_APPLE_NOTARY_KEY_ID" --issuer "$SEAWORTHY_APPLE_NOTARY_ISSUER" \
        --keychain "$keychain" >/dev/null || fail "notarytool refused the App Store Connect API key"
    apple_shred "$temp/AuthKey.p8"
    local identity="${SEAWORTHY_APPLE_IDENTITY:-}" installer=""
    if [ -z "$identity" ]; then
        identity="$(security find-identity -v -p codesigning "$keychain" |
            sed -n 's/^ *[0-9][0-9]*) [0-9A-F]\{40\} "\(Developer ID Application: .*\)"$/\1/p' | head -n1)"
        if [ -z "$identity" ]; then
            # Names only. A valid identity needs Apple's Developer ID
            # intermediate: an untrusted one (CSSMERR_TP_NOT_TRUSTED) says the
            # machine can't reach it, and it can ride along in the PKCS#12.
            security find-identity "$keychain" >&2 || true
            fail "the Developer ID PKCS#12 holds no valid Developer ID Application identity"
        fi
    fi
    installer="$(security find-identity -v "$keychain" |
        sed -n 's/^ *[0-9][0-9]*) [0-9A-F]\{40\} "\(Developer ID Installer: .*\)"$/\1/p' | head -n1)"
    apple_identity="$identity"
    apple_installer="$installer"
    apple_keychain_path="$keychain"
    apple_profile="$profile"
    say "Developer ID: $identity${installer:+; installer: $installer}"
}

# Run as a script: the step's wrapper (the header). Sourced, nothing below
# runs.
if [ "${BASH_SOURCE[0]}" != "$0" ]; then
    return 0
fi

set -euo pipefail
shopt -s inherit_errexit 2>/dev/null || true

fail() { echo "seaworthy (apple-keychain): FAIL: $*" >&2; exit 1; }
say() { echo "seaworthy (apple-keychain): $*"; }

file="${1:-}"
[ "$#" -ge 3 ] && [ "${2:-}" = -- ] || fail "usage: apple-keychain.sh <signing.toml> -- <command>…"
shift 2
[ -f "$file" ] || fail "the signing configuration $file doesn't exist"
if grep -q '^[[:space:]]*\[apple\]' "$file"; then
    fail "$file already has an [apple]: this script makes one, from the credentials in its environment"
fi

# In a subshell: the system's basics and these credentials alone in the
# environment. Whatever else the step's prefix handed over (the release
# manifests' key) is for the command, not for what makes the keychain.
only_basics() {
    local name
    while IFS= read -r name; do
        case "$name" in
            PATH | HOME | USER | LOGNAME | LANG | LC_ALL | TMPDIR | TZ | DEVELOPER_DIR | \
                SSL_CERT_FILE | SSL_CERT_DIR | http_proxy | https_proxy | no_proxy | \
                HTTP_PROXY | HTTPS_PROXY | NO_PROXY | ALL_PROXY | all_proxy | GITHUB_ACTIONS | \
                SEAWORTHY_APPLE_P12 | SEAWORTHY_APPLE_P12_PASSWORD | SEAWORTHY_APPLE_NOTARY_KEY | \
                SEAWORTHY_APPLE_NOTARY_KEY_ID | SEAWORTHY_APPLE_NOTARY_ISSUER | SEAWORTHY_APPLE_IDENTITY) ;;
            *) unset "$name" 2>/dev/null || true ;;
        esac
    done < <(compgen -e)
}

umask 077
dir="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/seaworthy-signing.XXXXXXXX")"
keychain="$dir/signing.keychain-db"
generated=""
cleanup() {
    local rc=$?
    if [ -f "$keychain" ]; then
        (
            only_basics
            security delete-keychain "$keychain"
        ) || true
        say "the signing keychain is deleted"
    fi
    if [ -d "$dir" ]; then
        local doomed
        while IFS= read -r -d '' doomed; do
            apple_shred "$doomed"
        done < <(find "$dir" -type f -print0)
        rm -rf -- "$dir"
    fi
    [ -z "$generated" ] || rm -f -- "$generated"
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# The keychain. The names it finds come back through a file in the private
# directory.
(
    only_basics
    apple_keychain "$dir"
    printf '%s\n' "$apple_identity" "$apple_installer" "$apple_keychain_path" "$apple_profile" > "$dir/names"
)
unset SEAWORTHY_APPLE_P12 SEAWORTHY_APPLE_P12_PASSWORD SEAWORTHY_APPLE_NOTARY_KEY \
    SEAWORTHY_APPLE_NOTARY_KEY_ID SEAWORTHY_APPLE_NOTARY_ISSUER SEAWORTHY_APPLE_IDENTITY
{
    IFS= read -r identity
    IFS= read -r installer
    IFS= read -r made
    IFS= read -r profile
} < "$dir/names"
[ "$made" = "$keychain" ] || fail "the keychain is at $made, not $keychain"

# signing.toml takes these as basic strings: nothing a string would escape.
for value in "$identity" "$installer" "$keychain" "$profile"; do
    if [[ "$value" == *[\"\\]* || "$value" =~ [[:cntrl:]] ]]; then
        fail "a Developer ID name or path holds a quote, a backslash or a control character"
    fi
done
generated="$(mktemp "$(dirname "$file")/.seaworthy-signing.XXXXXXXX")"
{
    cat "$file"
    printf '\n[apple]\nidentity = "%s"\nkeychain = "%s"\nnotary-profile = "%s"\n' "$identity" "$keychain" "$profile"
    [ -z "$installer" ] || printf 'installer-identity = "%s"\n' "$installer"
} > "$generated"

"$@" --signing "$generated"
