#!/usr/bin/env bash
# scripts/ci/github.sh — the GitHub Actions glue of seaworthy's reusable
# workflow (.github/workflows/dist.yml): what turns the workflow's typed
# inputs and secrets into what scripts/ci/seaworthy.sh and the seaworthy
# command read. The packaging logic stays in seaworthy.sh.
#
#   github.sh matrix <work>              the build matrix: one entry per
#                                        target directory of each plan
#                                        (GITHUB_OUTPUT lines)
#   github.sh build-env <triple> <file>  the caller's build-env for one
#                                        target, checked, as KEY=VALUE lines
#   github.sh data-path                  the caller's data artifact
#                                        (data-artifact) and where it lands
#                                        (data-path), checked before anything
#                                        downloads it: both or neither, a
#                                        plain relative path not there yet,
#                                        outside seaworthy's own directories
#   github.sh oidc-grant                 the calling job's grant, in the two
#                                        jobs that take it as it is (package,
#                                        adopt-msi): id-token: write with the
#                                        azure-* inputs (required when the run
#                                        signs), never without them
#   github.sh signing-toml <file>        signing.toml from the secrets the
#                                        job was handed (names, never values);
#                                        exports SEAWORTHY_SIGNING, or
#                                        SEAWORTHY_UNSIGNED=1 without a signer
#   github.sh signed <step>              seaworthy.sh <step> (package,
#                                        adopt-msi, package-macos, repo) with
#                                        its signing material made for it alone:
#                                        signing.toml and the Authenticode PEM
#                                        files (or, on macOS, the Developer ID
#                                        keychain) in a private directory that
#                                        is shredded (keychain deleted) when the
#                                        step ends, however it ends
#   github.sh apple-cleanup              macOS: any keychain a cancelled step
#                                        left, deleted (the always-run step)
#   github.sh assemble <out> <label>=<dir>...
#                                        every listed artifact, checked
#                                        against its listing's SHA-256, into
#                                        <out>/<label>/, with SHA256SUMS
#   github.sh delete-artifacts [pattern] this run's artifacts whose names
#                                        match the bash pattern (every one
#                                        by default), deleted through gh
#                                        (delete-artifacts.yml)
#
# Environment (the workflow sets it; the secrets only on a release or a
# dev build, and only in the jobs that sign):
#
#   SEAWORTHY_PLATFORMS                 matrix: linux, windows, macos (comma)
#   SEAWORTHY_DATA_ARTIFACT             data-path: the inputs; with
#   SEAWORTHY_DATA_PATH                   SEAWORTHY_CHECKOUT and
#                                         SEAWORTHY_WORK, the directories
#                                         the data may never reach
#   SEAWORTHY_BUILD_ENV                 build-env: a JSON object of objects,
#                                       {"<triple>" or "*": {"NAME": "value"}}
#   SEAWORTHY_GH_MANIFEST_ALGORITHM     signing-toml: the release-manifest
#   SEAWORTHY_RELEASE_MANIFEST_KEY        key's algorithm, and its hex
#   SEAWORTHY_GH_OPENPGP_FINGERPRINT    signing-toml: the OpenPGP key's
#   SEAWORTHY_OPENPGP_SECRET_KEY          fingerprint, and the armored key
#   SEAWORTHY_GH_AUTHENTICODE_PFX       signing-toml: a PKCS#12 file
#   SEAWORTHY_GH_AUTHENTICODE_PASSWORD    (base64), its password, and the
#   SEAWORTHY_GH_TIMESTAMP_URL            RFC 3161 service to timestamp with
#   SEAWORTHY_GH_AZURE_ENDPOINT         signing-toml: Azure Artifact Signing
#   SEAWORTHY_GH_AZURE_ACCOUNT            (with AZURE_TENANT_ID and
#   SEAWORTHY_GH_AZURE_PROFILE            AZURE_CLIENT_ID; OIDC, no secret)
#   SEAWORTHY_GH_APPLE_*                apple-keychain: the identities'
#                                       PKCS#12 (base64) and password, the
#                                       App Store Connect API key (.p8,
#                                       armored or base64), its id and issuer;
#                                       signing-toml: the identities, keychain
#                                       and notary profile apple-keychain set
#   SEAWORTHY_GH_SCRIPTS                signing-toml: where azure-sign.sh is
#                                       (default: beside this script)
#   SIGNING_TOML                        signed: the caller's own signing.toml,
#                                       used instead of one made from secrets
#   SEAWORTHY_RELEASE, SEAWORTHY_DEV_SIGN
#                                       signed: whether the step signs at all;
#                                       signing-toml: a release or a dev build
#                                       with no signer is refused unless
#                                       SEAWORTHY_ALLOW_UNSIGNED=1
#   GITHUB_REPOSITORY, GITHUB_RUN_ID    delete-artifacts: the run (the
#   GH_TOKEN                              runner sets the first two), and a
#                                         token with actions: write
#
# Every value that reaches a file is checked first; secrets go to files
# only under a private directory (umask 077), which `signed` shreds when its
# step ends, and are never printed or put on a command line.
set -euo pipefail
# inherit_errexit (bash 4.4+) where the shell has it: macOS runners' bash is
# 3.2, so nothing here relies on it; `quoted` stands in for the 4.4
# `${var@Q}` expansion.
shopt -s inherit_errexit 2>/dev/null || true
quoted() { printf '%q' "$1"; }
# SHA-256 of files: coreutils' sha256sum, else macOS's shasum (the same
# output format).
if command -v sha256sum >/dev/null 2>&1; then sha256=(sha256sum); else sha256=(shasum -a 256); fi
# OpenSSL proper: macOS's /usr/bin/openssl is LibreSSL, which can't open the
# PKCS#12 files OpenSSL 3 writes, so Homebrew's OpenSSL 3 comes first.
openssl() {
    local brew
    for brew in /opt/homebrew/opt/openssl@3/bin/openssl /usr/local/opt/openssl@3/bin/openssl; do
        if [ -x "$brew" ]; then "$brew" "$@"; return; fi
    done
    command openssl "$@"
}

fail() { echo "seaworthy (github): FAIL: $*" >&2; exit 1; }
lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }
say() { echo "seaworthy (github): $*"; }
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

# Appends `name=value` to $GITHUB_OUTPUT (or prints it outside Actions).
output() { # <name> <value>
    [[ "$2" != *[$'\n\r']* ]] || fail "$1 holds a line break"
    if [ -n "${GITHUB_OUTPUT:-}" ]; then
        printf '%s=%s\n' "$1" "$2" >> "$GITHUB_OUTPUT"
    else
        printf '%s=%s\n' "$1" "$2"
    fi
}

# Exports `name=value` to the job's later steps ($GITHUB_ENV), or prints it.
export_env() { # <name> <value>
    [[ "$2" != *[$'\n\r']* ]] || fail "$1 holds a line break"
    if [ -n "${GITHUB_ENV:-}" ]; then
        printf '%s=%s\n' "$1" "$2" >> "$GITHUB_ENV"
    else
        printf '%s=%s\n' "$1" "$2"
    fi
}

# The build matrix: each plan's target directories, in plan order, as JSON
# arrays (linux, windows, macos), empty for a platform the caller left out
# or no product needs.
matrix() { # <work>
    local work="$1" platforms="${SEAWORTHY_PLATFORMS:-linux,windows,macos}"
    platforms=",${platforms//[[:space:]]/},"
    # A loop, not grep: BSD grep (macOS) reads an empty alternative as
    # matching every line.
    local unknown="" platform list
    IFS=',' read -r -a list <<<"$platforms"
    for platform in "${list[@]}"; do
        case "$platform" in '' | linux | windows | macos) ;; *) unknown+="$platform " ;; esac
    done
    [ -z "$unknown" ] || fail "platforms: unknown platform(s) $unknown(linux, windows, macos)"
    local platform triple dirs
    for platform in linux windows macos; do
        case "$platform" in
            linux) triple=x86_64-unknown-linux-gnu ;;
            windows) triple=x86_64-pc-windows-msvc ;;
            macos) triple=aarch64-apple-darwin ;;
        esac
        dirs='[]'
        if [[ "$platforms" == *",$platform,"* ]] && [ -f "$work/plan-$triple.tsv" ]; then
            dirs="$(awk -F'\t' '$1 == "build" && !seen[$2]++ { print $2 }' "$work/plan-$triple.tsv" |
                jq -R . | jq -cs .)"
        fi
        output "$platform" "$dirs"
        say "$platform ($triple): $dirs"
    done
}

# The variables the caller's build-env may not set: the runner's own, the
# loader's and the shell's, and those that would replace the per-CPU flags
# or move the builds (seaworthy's build step refuses them too).
reserved_variable() { # <name>
    case "$1" in
        GITHUB_* | RUNNER_* | ACTIONS_* | SEAWORTHY_* | INPUT_* | STATE_*) return 0 ;;
        PATH | HOME | SHELL | ENV | BASH_ENV | IFS | CDPATH | NODE_OPTIONS | LD_* | DYLD_*) return 0 ;;
        RUSTFLAGS | CARGO_ENCODED_RUSTFLAGS | CARGO_BUILD_RUSTFLAGS | CARGO_TARGET_DIR | CARGO_BUILD_TARGET_DIR) return 0 ;;
        CARGO_HOME | RUSTUP_HOME | RUSTUP_TOOLCHAIN) return 0 ;;
    esac
    return 1
}

# The caller's build-env for <triple>: "*" then the triple's own, each name
# a plain variable name nothing reserves, each value one line; written to
# <file> as KEY=VALUE lines (GITHUB_ENV's and docker's --env-file format).
build_env() { # <triple> <file>
    local triple="$1" file="$2" json="${SEAWORTHY_BUILD_ENV:-}"
    : > "$file"
    [ -n "${json//[[:space:]]/}" ] || return 0
    jq -e 'type == "object" and all(.[]; type == "object" and all(.[]; type == "string"))' \
        >/dev/null 2>&1 <<<"$json" ||
        fail "build-env must be a JSON object of objects of strings: {\"<triple>\" or \"*\": {\"NAME\": \"value\"}}"
    local keys
    keys="$(jq -r 'keys[]' <<<"$json")"
    local key
    while IFS= read -r key; do
        [ -n "$key" ] || continue
        case "$key" in
            '*' | x86_64-unknown-linux-gnu | x86_64-pc-windows-msvc | aarch64-apple-darwin) ;;
            *) fail "build-env: $(quoted "$key") is neither \"*\" nor a target seaworthy builds" ;;
        esac
    done <<<"$keys"
    jq -e '[.[][] | test("[\\x00-\\x1f\\x7f]")] | any | not' >/dev/null <<<"$json" ||
        fail "build-env: a value holds a control character (a newline, a tab)"
    local name value count=0
    # Name and value NUL-separated, the triple's own after "*" (so they win).
    while IFS= read -r -d '' name && IFS= read -r -d '' value; do
        [[ "$name" =~ ^[A-Za-z_][A-Za-z0-9_]{0,127}$ ]] || fail "build-env: $(quoted "$name") isn't a variable name"
        if reserved_variable "$name"; then
            fail "build-env may not set $name"
        fi
        printf '%s=%s\n' "$name" "$value" >> "$file"
        count=$((count + 1))
    done < <(jq -j --arg t "$triple" '((.["*"] // {}) + (.[$t] // {})) | to_entries[] | .key, "\u0000", .value, "\u0000"' <<<"$json")
    say "build-env: $count variable(s) for $triple"
}

# Refuses a value a TOML basic string would have to escape (a quote, a
# backslash, a control character). Called directly, never in a command
# substitution, so a refusal stops the step.
check_plain() { # <value>...
    local value
    for value in "$@"; do
        if [[ "$value" == *[\"\\]* || "$value" =~ [[:cntrl:]] ]]; then
            fail "a signing value holds a quote, a backslash or a control character"
        fi
    done
}

# signing.toml, from what the job was handed: a manifest signer by key-env,
# an OpenPGP signer by secret-key-env, Authenticode by a PKCS#12 converted
# to PEM files in a private directory or by azure-sign.sh (OIDC), and the
# Developer ID apple-keychain set up. Names and paths only.
# The calling job's grant, in a job that declares no permissions of its own
# and so has exactly that grant: the runner sets the OIDC request variables
# (ACTIONS_ID_TOKEN_REQUEST_*) for the whole job when it includes
# id-token: write. That grant is Azure Artifact Signing's alone: refused
# without the azure-* inputs (the job would hold a token it never uses),
# required with them when the run signs (a release or a dev build).
# The caller's data artifact (data-artifact: built by a job of the
# caller's, a web build say) and where the packaging jobs unpack it
# (data-path), for seaworthy.toml's [[files]] to read. Checked in the
# workspace (the current directory) before anything downloads it: both or
# neither; the artifact a name; the path plain and relative ([A-Za-z0-9._-]
# segments, no `.` or `..`), not there yet (the artifact never mixes with
# the repository's own files), and its existing part resolving, links
# followed, inside the workspace and outside seaworthy's checkout and work
# directory (case-insensitively, as macOS's file system compares): the
# scripts and tool the signing step runs live there, and the data must
# never land on them.
data_path() {
    local artifact="${SEAWORTHY_DATA_ARTIFACT:-}" path="${SEAWORTHY_DATA_PATH:-}"
    if [ -z "$artifact" ] && [ -z "$path" ]; then
        say "no data artifact"
        return 0
    fi
    [ -n "$artifact" ] || fail "data-path is set without data-artifact: name the artifact to unpack there"
    [ -n "$path" ] || fail "data-artifact is set without data-path: name where to unpack it, relative to the repository's root"
    [[ "$artifact" =~ ^[A-Za-z0-9._-]{1,128}$ ]] ||
        fail "data-artifact $(quoted "$artifact") isn't an artifact's name ([A-Za-z0-9._-], at most 128)"
    [[ "$path" =~ ^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$ ]] ||
        fail "data-path $(quoted "$path") isn't a plain relative path ([A-Za-z0-9._-] segments joined by /)"
    local segment
    local -a segments
    IFS=/ read -r -a segments <<<"$path"
    for segment in "${segments[@]}"; do
        case "$segment" in
            . | ..) fail "data-path $(quoted "$path") holds a \`$segment\` segment" ;;
        esac
    done
    local root checkout work parent resolved landing place
    root="$(pwd -P)"
    checkout="$(lower "$root/${SEAWORTHY_CHECKOUT:-.seaworthy}")"
    work="$(lower "$root/${SEAWORTHY_WORK:-seaworthy-work}")"
    # The nearest part of it that exists: a directory, resolved.
    parent="$(dirname "$path")"
    while [ "$parent" != . ] && [ ! -e "$parent" ] && [ ! -L "$parent" ]; do
        parent="$(dirname "$parent")"
    done
    [ -d "$parent" ] || fail "data-path $(quoted "$path"): $(quoted "$parent") isn't a directory"
    resolved="$(cd "$parent" && pwd -P)" || fail "data-path $(quoted "$path"): $(quoted "$parent") can't be entered"
    case "$resolved/" in
        "$root"/*) ;;
        *) fail "data-path $(quoted "$path") leads out of the workspace (through $(quoted "$parent"))" ;;
    esac
    # Where it will be: the resolved part, then the parts made anew.
    landing="$(lower "$resolved/${path#"$parent"/}")"
    [ "$parent" != . ] || landing="$(lower "$resolved/$path")"
    for place in "$checkout" "$work"; do
        case "$landing/" in
            "$place"/*) fail "data-path $(quoted "$path") lands in seaworthy's own $(quoted "${place##*/}"): unpack the data elsewhere" ;;
        esac
    done
    # Last: on a file system that ignores case (macOS's), seaworthy's own directories spelled
    # otherwise are there already, and are refused above for what they are.
    if [ -e "$path" ] || [ -L "$path" ]; then
        fail "data-path $(quoted "$path") is in the repository already: unpack the artifact where nothing is"
    fi
    say "the data artifact $artifact lands in $path"
}

oidc_grant() {
    local azure=0 granted=0
    [ -z "${SEAWORTHY_GH_AZURE_ENDPOINT:-}${SEAWORTHY_GH_AZURE_ACCOUNT:-}${SEAWORTHY_GH_AZURE_PROFILE:-}${AZURE_TENANT_ID:-}${AZURE_CLIENT_ID:-}" ] ||
        azure=1
    [ -z "${ACTIONS_ID_TOKEN_REQUEST_URL:-}${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ] || granted=1
    if [ "$azure" = 0 ] && [ "$granted" = 1 ]; then
        fail "the job that calls dist.yml grants id-token: write, which only Azure Artifact Signing (the azure-* inputs) uses: remove it from that job's permissions"
    fi
    if [ "$azure" = 1 ] && [ "$granted" = 0 ]; then
        if [ "${SEAWORTHY_RELEASE:-0}" = 1 ] || [ "${SEAWORTHY_DEV_SIGN:-0}" = 1 ]; then
            fail "Azure Artifact Signing (the azure-* inputs) needs an OIDC token: grant id-token: write in the job that calls dist.yml"
        fi
        say "no id-token: write grant: the azure-* inputs sign only a release or a dev build"
        return 0
    fi
    if [ "$granted" = 1 ]; then
        say "the calling job grants id-token: write, for Azure Artifact Signing"
    else
        say "the calling job grants no id-token: write (no Azure Artifact Signing)"
    fi
}

signed_file="" signed_unsigned=0
signing_toml() { # <file>
    local file="$1" sections=()
    local dir
    dir="$(dirname "$file")"
    mkdir -p "$dir"
    umask 077
    : > "$file"
    if [ -n "${SEAWORTHY_RELEASE_MANIFEST_KEY:-}" ]; then
        local algorithm="${SEAWORTHY_GH_MANIFEST_ALGORITHM:-}"
        case "$algorithm" in
            ml-dsa-87 | ecdsa-p256 | ed25519) ;;
            "") fail "the RELEASE_MANIFEST_KEY secret needs the release-manifest-algorithm input (ml-dsa-87, ecdsa-p256 or ed25519)" ;;
            *) fail "release-manifest-algorithm $(quoted "$algorithm"): ml-dsa-87, ecdsa-p256 or ed25519" ;;
        esac
        printf '[[manifest]]\nalgorithm = "%s"\nkey-env = "SEAWORTHY_RELEASE_MANIFEST_KEY"\n\n' \
            "$algorithm" >> "$file"
        sections+=("manifest ($algorithm)")
    fi
    if [ -n "${SEAWORTHY_OPENPGP_SECRET_KEY:-}" ]; then
        local fingerprint="${SEAWORTHY_GH_OPENPGP_FINGERPRINT:-}"
        [[ "$fingerprint" =~ ^([0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})$ ]] ||
            fail "the OPENPGP_SECRET_KEY secret needs the openpgp-key-fingerprint input (40 or 64 hex characters)"
        printf '[openpgp]\nsecret-key-env = "SEAWORTHY_OPENPGP_SECRET_KEY"\nkey = "%s"\n\n' \
            "$fingerprint" >> "$file"
        sections+=("openpgp")
    fi
    local azure=0 pfx=0
    [ -z "${SEAWORTHY_GH_AZURE_ENDPOINT:-}${SEAWORTHY_GH_AZURE_ACCOUNT:-}${SEAWORTHY_GH_AZURE_PROFILE:-}" ] || azure=1
    [ -z "${SEAWORTHY_GH_AUTHENTICODE_PFX:-}" ] || pfx=1
    [ $((azure + pfx)) -le 1 ] || fail "Authenticode: give either the AUTHENTICODE_PFX secret or the azure-* inputs, not both"
    if [ "$azure" = 1 ]; then
        local endpoint="${SEAWORTHY_GH_AZURE_ENDPOINT:-}" account="${SEAWORTHY_GH_AZURE_ACCOUNT:-}"
        local profile="${SEAWORTHY_GH_AZURE_PROFILE:-}" scripts="${SEAWORTHY_GH_SCRIPTS:-}"
        [[ "$endpoint" =~ ^[a-z0-9]+\.codesigning\.azure\.net$ ]] || fail "azure-endpoint: <region>.codesigning.azure.net"
        [[ "$account" =~ ^[A-Za-z0-9-]{3,64}$ ]] || fail "azure-account: an Artifact Signing account name"
        [[ "$profile" =~ ^[A-Za-z0-9-]{3,64}$ ]] || fail "azure-profile: a certificate profile name"
        [ -n "${AZURE_TENANT_ID:-}" ] && [ -n "${AZURE_CLIENT_ID:-}" ] || fail "Azure Artifact Signing needs the azure-tenant-id and azure-client-id inputs"
        scripts="${scripts:-$here}"
        [ -f "$scripts/azure-sign.sh" ] || fail "no azure-sign.sh in $(quoted "$scripts")"
        check_plain "$scripts/azure-sign.sh"
        printf '[authenticode]\ncommand = ["bash", "%s", "--endpoint", "%s", "--account", "%s", "--profile", "%s", "{file}"]\n\n' \
            "$scripts/azure-sign.sh" "$endpoint" "$account" "$profile" >> "$file"
        sections+=("authenticode (Azure Artifact Signing)")
    elif [ "$pfx" = 1 ]; then
        local url="${SEAWORTHY_GH_TIMESTAMP_URL:-}"
        [[ "$url" =~ ^https?://[A-Za-z0-9.-]+(:[0-9]+)?(/[A-Za-z0-9._~/-]*)?$ ]] ||
            fail "the AUTHENTICODE_PFX secret needs the authenticode-timestamp-url input (an RFC 3161 service's http(s) URL)"
        command -v openssl >/dev/null 2>&1 || fail "openssl is required to read the PKCS#12 file"
        local keys="$dir/authenticode"
        mkdir -p "$keys"
        base64 -d > "$keys/identity.p12" <<<"$SEAWORTHY_GH_AUTHENTICODE_PFX" ||
            fail "the AUTHENTICODE_PFX secret isn't base64"
        export SEAWORTHY_GH_AUTHENTICODE_PASSWORD="${SEAWORTHY_GH_AUTHENTICODE_PASSWORD:-}"
        # OpenSSL 3 refuses the legacy (RC2/3DES) encryption older tools
        # export with unless asked; the password through the environment.
        local legacy=()
        openssl pkcs12 -in "$keys/identity.p12" -passin env:SEAWORTHY_GH_AUTHENTICODE_PASSWORD -noout 2>/dev/null ||
            legacy=(-legacy)
        { openssl pkcs12 "${legacy[@]}" -in "$keys/identity.p12" -passin env:SEAWORTHY_GH_AUTHENTICODE_PASSWORD \
            -clcerts -nokeys &&
            openssl pkcs12 "${legacy[@]}" -in "$keys/identity.p12" -passin env:SEAWORTHY_GH_AUTHENTICODE_PASSWORD \
                -cacerts -nokeys; } 2>/dev/null | sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' \
            > "$keys/chain.pem" || fail "the AUTHENTICODE_PFX secret doesn't open with its password"
        openssl pkcs12 "${legacy[@]}" -in "$keys/identity.p12" -passin env:SEAWORTHY_GH_AUTHENTICODE_PASSWORD \
            -nocerts -nodes 2>/dev/null | sed -n '/-----BEGIN .*PRIVATE KEY-----/,/-----END .*PRIVATE KEY-----/p' \
            > "$keys/key.pem" || fail "the AUTHENTICODE_PFX secret holds no key"
        rm -f "$keys/identity.p12"
        [ -s "$keys/chain.pem" ] && [ -s "$keys/key.pem" ] || fail "the AUTHENTICODE_PFX secret holds no certificate and key"
        chmod 0600 "$keys/chain.pem" "$keys/key.pem"
        check_plain "$keys"
        printf '[authenticode]\ncertificate = "%s"\nkey = "%s"\ntimestamp-url = "%s"\n\n' \
            "$keys/chain.pem" "$keys/key.pem" "$url" >> "$file"
        sections+=("authenticode (PKCS#12)")
    fi
    if [ -n "${SEAWORTHY_GH_APPLE_IDENTITY:-}" ]; then
        check_plain "$SEAWORTHY_GH_APPLE_IDENTITY" "${SEAWORTHY_GH_APPLE_KEYCHAIN:-}" \
            "${SEAWORTHY_GH_APPLE_NOTARY_PROFILE:-}" "${SEAWORTHY_GH_APPLE_INSTALLER_IDENTITY:-}"
        printf '[apple]\nidentity = "%s"\nkeychain = "%s"\nnotary-profile = "%s"\n' \
            "$SEAWORTHY_GH_APPLE_IDENTITY" "${SEAWORTHY_GH_APPLE_KEYCHAIN:-}" \
            "${SEAWORTHY_GH_APPLE_NOTARY_PROFILE:-}" >> "$file"
        [ -z "${SEAWORTHY_GH_APPLE_INSTALLER_IDENTITY:-}" ] ||
            printf 'installer-identity = "%s"\n' "$SEAWORTHY_GH_APPLE_INSTALLER_IDENTITY" >> "$file"
        printf '\n' >> "$file"
        sections+=("apple (Developer ID)")
    fi
    # The file, or (no signer at all) an unsigned build: refused on a
    # release or a dev build unless SEAWORTHY_ALLOW_UNSIGNED=1 means it, as a
    # secret that didn't reach the job must not quietly ship unsigned.
    if [ "${#sections[@]}" -eq 0 ]; then
        if [ "${SEAWORTHY_RELEASE:-0}" = 1 ] || [ "${SEAWORTHY_DEV_SIGN:-0}" = 1 ]; then
            [ "${SEAWORTHY_ALLOW_UNSIGNED:-0}" = 1 ] ||
                fail "no signer was handed to this job, on a release or a dev build: pass the signing secrets (or signing-toml), or allow an unsigned build on purpose with the allow-unsigned input"
            echo "::warning::seaworthy: no signer was handed to this job: an UNSIGNED build (allow-unsigned)"
        fi
        say "signing.toml: no signer was handed to this job: an unsigned build"
        signed_unsigned=1
    else
        say "signing.toml: ${sections[*]}"
        signed_file="$file"
    fi
}

# macOS: the Developer ID identities imported into a keychain of their own
# in <dir> (a random password, locked after two hours: the package step's
# longest run, notarization included; `signed` deletes it when the step
# ends), first in the search list, and the notary service's API key stored
# as a notarytool profile in it. Sets the identities' names, the keychain
# and the profile for signing-toml. The PKCS#12's password reaches openssl
# alone, through its environment: each identity is re-wrapped under a
# throwaway password, which is what `security import` (which takes one only
# as -P, on its command line) sees.
apple_keychain() { # <dir>
    [ "$(uname -s)" = Darwin ] || fail "the Developer ID keychain is made on macOS"
    [ -n "${SEAWORTHY_GH_APPLE_P12:-}" ] || fail "no APPLE_CERTIFICATE_P12 secret"
    for variable in SEAWORTHY_GH_APPLE_NOTARY_KEY SEAWORTHY_GH_APPLE_NOTARY_KEY_ID SEAWORTHY_GH_APPLE_NOTARY_ISSUER; do
        [ -n "${!variable:-}" ] || fail "Developer ID signing notarizes: the APPLE_NOTARY_KEY, APPLE_NOTARY_KEY_ID and APPLE_NOTARY_ISSUER secrets are required"
    done
    [[ "$SEAWORTHY_GH_APPLE_NOTARY_KEY_ID" =~ ^[A-Z0-9]{6,20}$ ]] || fail "APPLE_NOTARY_KEY_ID isn't an App Store Connect key id"
    [[ "$SEAWORTHY_GH_APPLE_NOTARY_ISSUER" =~ ^[0-9a-fA-F-]{36}$ ]] || fail "APPLE_NOTARY_ISSUER isn't an issuer id (a UUID)"
    local temp="$1/apple"
    umask 077
    mkdir -p "$temp"
    local keychain="$1/signing.keychain-db" password profile=seaworthy-notary throwaway
    password="$(openssl rand -hex 24)"
    throwaway="$(openssl rand -hex 24)"
    echo "::add-mask::$password"
    echo "::add-mask::$throwaway"
    security create-keychain -p "$password" "$keychain"
    security set-keychain-settings -lut 7200 "$keychain"
    security unlock-keychain -p "$password" "$keychain"
    base64 -d > "$temp/identity.p12" <<<"$SEAWORTHY_GH_APPLE_P12" || fail "APPLE_CERTIFICATE_P12 isn't base64"
    local legacy=()
    SEAWORTHY_P12_IN="${SEAWORTHY_GH_APPLE_P12_PASSWORD:-}" \
        openssl pkcs12 -in "$temp/identity.p12" -passin env:SEAWORTHY_P12_IN -noout 2>/dev/null ||
        legacy=(-legacy)
    SEAWORTHY_P12_IN="${SEAWORTHY_GH_APPLE_P12_PASSWORD:-}" \
        openssl pkcs12 "${legacy[@]}" -in "$temp/identity.p12" -passin env:SEAWORTHY_P12_IN \
        -nokeys -out "$temp/certificates.pem" 2>/dev/null ||
        fail "APPLE_CERTIFICATE_P12 doesn't open with APPLE_CERTIFICATE_PASSWORD"
    # Each private key into a file of its own (the Application and the
    # Installer identities share one PKCS#12).
    SEAWORTHY_P12_IN="${SEAWORTHY_GH_APPLE_P12_PASSWORD:-}" \
        openssl pkcs12 "${legacy[@]}" -in "$temp/identity.p12" -passin env:SEAWORTHY_P12_IN \
        -nocerts -nodes 2>/dev/null |
        awk -v dir="$temp" '/^-----BEGIN [A-Z ]*PRIVATE KEY-----$/ { n++; file = dir "/key-" n ".pem" }
            file { print > file }
            /^-----END [A-Z ]*PRIVATE KEY-----$/ { close(file); file = "" }' ||
        fail "APPLE_CERTIFICATE_P12's keys don't open with APPLE_CERTIFICATE_PASSWORD"
    rm -f "$temp/identity.p12"
    local keys=("$temp"/key-*.pem) key
    [ -f "${keys[0]}" ] || fail "APPLE_CERTIFICATE_P12 holds no private key"
    for key in "${keys[@]}"; do
        # The certificate matching the key leads; the others ride along.
        SEAWORTHY_P12_OUT="$throwaway" openssl pkcs12 -export -inkey "$key" -in "$temp/certificates.pem" \
            -passout env:SEAWORTHY_P12_OUT -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg sha1 \
            -out "$key.p12" 2>/dev/null || fail "an APPLE_CERTIFICATE_P12 key has no certificate"
        shred_files "$key"
        security import "$key.p12" -k "$keychain" -f pkcs12 -P "$throwaway" \
            -T /usr/bin/codesign -T /usr/bin/productbuild >/dev/null ||
            fail "an APPLE_CERTIFICATE_P12 identity doesn't import into the keychain"
        shred_files "$key.p12"
    done
    shred_files "$temp/certificates.pem"
    security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$password" "$keychain" >/dev/null
    # This keychain first, the user's others after it.
    local existing=()
    while IFS= read -r line; do
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line#\"}"
        line="${line%\"}"
        [ -n "$line" ] && existing+=("$line")
    done < <(security list-keychains -d user)
    security list-keychains -d user -s "$keychain" "${existing[@]}"
    if [[ "$SEAWORTHY_GH_APPLE_NOTARY_KEY" == -----BEGIN* ]]; then
        printf '%s\n' "$SEAWORTHY_GH_APPLE_NOTARY_KEY" > "$temp/AuthKey.p8"
    else
        base64 -d > "$temp/AuthKey.p8" <<<"$SEAWORTHY_GH_APPLE_NOTARY_KEY" || fail "APPLE_NOTARY_KEY is neither a .p8 key nor base64"
    fi
    xcrun notarytool store-credentials "$profile" --key "$temp/AuthKey.p8" \
        --key-id "$SEAWORTHY_GH_APPLE_NOTARY_KEY_ID" --issuer "$SEAWORTHY_GH_APPLE_NOTARY_ISSUER" \
        --keychain "$keychain" >/dev/null || fail "notarytool refused the API key (APPLE_NOTARY_KEY, _KEY_ID, _ISSUER)"
    shred_files "$temp/AuthKey.p8"
    local identity="${SEAWORTHY_GH_APPLE_IDENTITY:-}" installer=""
    if [ -z "$identity" ]; then
        identity="$(security find-identity -v -p codesigning "$keychain" |
            sed -n 's/^ *[0-9][0-9]*) [0-9A-F]\{40\} "\(Developer ID Application: .*\)"$/\1/p' | head -n1)"
        [ -n "$identity" ] || fail "APPLE_CERTIFICATE_P12 holds no Developer ID Application identity"
    fi
    installer="$(security find-identity -v "$keychain" |
        sed -n 's/^ *[0-9][0-9]*) [0-9A-F]\{40\} "\(Developer ID Installer: .*\)"$/\1/p' | head -n1)"
    SEAWORTHY_GH_APPLE_IDENTITY="$identity"
    SEAWORTHY_GH_APPLE_INSTALLER_IDENTITY="$installer"
    SEAWORTHY_GH_APPLE_KEYCHAIN="$keychain"
    SEAWORTHY_GH_APPLE_NOTARY_PROFILE="$profile"
    say "Developer ID: $identity${installer:+; installer: $installer}"
}

# Every keychain a signing step made (signed deletes its own; this is the
# always-run step's, for a step that was killed).
apple_cleanup() {
    local keychain
    for keychain in "${RUNNER_TEMP:-/nonexistent}"/seaworthy-signing.*/signing.keychain-db; do
        [ -f "$keychain" ] || continue
        security delete-keychain "$keychain" || true
        say "the signing keychain is deleted"
    done
}

# Overwrites and removes files (GNU shred where there is one; macOS's
# filesystems give no such guarantee, so there they're only removed).
shred_files() { # <file>...
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

# Shreds every file under <dir>, then removes it.
shred_dir() { # <dir>
    [ -d "$1" ] || return 0
    local file
    while IFS= read -r -d '' file; do
        shred_files "$file"
    done < <(find "$1" -type f -print0)
    rm -rf -- "$1"
}

# seaworthy.sh <step> with its signing material made for it alone. On a
# release or a dev build: a private directory under RUNNER_TEMP holds
# signing.toml, the Authenticode PEM files the PKCS#12 secret opens to, and
# on macOS (package-macos with the Apple secrets) the Developer ID keychain;
# the step runs, then the keychain is deleted and the directory shredded,
# whether the step passed, failed or was interrupted. The secrets that
# became files leave the environment before seaworthy.sh starts, and
# seaworthy.sh hands the rest to its seaworthy call alone. Outside a
# release or a dev build nothing signs: seaworthy.sh <step> as it is.
signed_dir="" signed_keychain=""
signed_cleanup() {
    if [ -n "$signed_keychain" ] && [ -f "$signed_keychain" ]; then
        security delete-keychain "$signed_keychain" || true
        say "the signing keychain is deleted"
    fi
    [ -z "$signed_dir" ] || shred_dir "$signed_dir"
}
signed() { # <step>
    local step="$1"
    case "$step" in
        package | adopt-msi | package-macos | repo) ;;
        *) fail "signed: package, adopt-msi, package-macos or repo, not $(quoted "$step")" ;;
    esac
    if [ "${SEAWORTHY_RELEASE:-0}" != 1 ] && [ "${SEAWORTHY_DEV_SIGN:-0}" != 1 ]; then
        exec bash "$here/seaworthy.sh" "$step"
    fi
    if [ "$step" = package-macos ] && { [ "${SEAWORTHY_RELEASE:-0}" != 1 ] || [ -z "${SEAWORTHY_GH_APPLE_P12:-}" ]; }; then
        # No Developer ID: the macOS outputs stay ad hoc-signed, outside the
        # release.
        unset SEAWORTHY_GH_APPLE_P12 SEAWORTHY_GH_APPLE_P12_PASSWORD SEAWORTHY_GH_APPLE_NOTARY_KEY
        exec bash "$here/seaworthy.sh" "$step"
    fi
    trap signed_cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    signed_dir="$(umask 077 && mktemp -d "${RUNNER_TEMP:?RUNNER_TEMP is unset}/seaworthy-signing.XXXXXXXX")"
    if [ "$step" = package-macos ]; then
        signed_keychain="$signed_dir/signing.keychain-db"
        apple_keychain "$signed_dir"
        export SEAWORTHY_MACOS_SIGN=1
    fi
    if [ -n "${SIGNING_TOML:-}" ]; then
        [[ "$SIGNING_TOML" != *[[:cntrl:]]* ]] || fail "signing-toml holds a control character"
        export SEAWORTHY_SIGNING="$SIGNING_TOML"
        say "signing.toml: the caller's $SIGNING_TOML"
    else
        signing_toml "$signed_dir/signing.toml"
        if [ "$signed_unsigned" = 1 ]; then
            export SEAWORTHY_UNSIGNED=1
        else
            export SEAWORTHY_SIGNING="$signed_file"
        fi
    fi
    # What became files leaves the environment.
    unset SEAWORTHY_GH_AUTHENTICODE_PFX SEAWORTHY_GH_AUTHENTICODE_PASSWORD \
        SEAWORTHY_GH_APPLE_P12 SEAWORTHY_GH_APPLE_P12_PASSWORD SEAWORTHY_GH_APPLE_NOTARY_KEY
    bash "$here/seaworthy.sh" "$step"
}

# Every listing's artifacts, read once, checked against the SHA-256 the
# listing gives, copied with the listing into <out>/<label>/<product>/;
# then SHA256SUMS over everything copied.
assemble() { # <out> <label>=<dir>...
    local out="$1"
    shift
    [ ! -e "$out" ] || fail "assemble: $out exists"
    mkdir -p "$out"
    local pair label dir listing product files=0
    for pair in "$@"; do
        label="${pair%%=*}" dir="${pair#*=}"
        [[ "$label" =~ ^[a-z0-9-]+$ ]] || fail "assemble: $(quoted "$label") isn't a label"
        [ -d "$dir" ] || { say "assemble: no $dir ($label): nothing from it"; continue; }
        for listing in "$dir"/*/packages.json; do
            [ -f "$listing" ] || continue
            product="$(basename "$(dirname "$listing")")"
            mkdir -p "$out/$label/$product"
            cp "$listing" "$out/$label/$product/packages.json"
            local file sha actual
            while IFS=$'\t' read -r file sha; do
                [[ "$file" =~ ^[A-Za-z0-9._+~-]+(/[A-Za-z0-9._+~-]+)*$ && "$file" != *..* ]] ||
                    fail "$listing lists $(quoted "$file"), not a plain relative path"
                [[ "$sha" =~ ^[0-9a-f]{64}$ ]] || fail "$listing: ${file}'s SHA-256 isn't one"
                local from to
                from="$(dirname "$listing")/$file" to="$out/$label/$product/$file"
                [ -f "$from" ] && [ ! -L "$from" ] || fail "$listing lists $file, which isn't there"
                mkdir -p "$(dirname "$to")"
                cp "$from" "$to"
                actual="$("${sha256[@]}" "$to" | cut -d' ' -f1)"
                [ "$actual" = "$sha" ] || fail "$label/$product/$file: SHA-256 $actual, but the listing says $sha"
                files=$((files + 1))
            done < <(jq -r '.artifacts[] | [.file, .sha256] | @tsv' "$listing")
        done
    done
    [ "$files" -gt 0 ] || fail "assemble: no listed artifact anywhere"
    local sums
    sums="$(cd "$out" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 "${sha256[@]}" | sed 's#  \./#  #')"
    printf '%s\n' "$sums" > "$out/SHA256SUMS"
    say "assembled $files artifact(s) into $out, checked against their listings (SHA256SUMS)"
}

# This run's artifacts whose names match <pattern> (a bash pattern), deleted
# through the GitHub API. The whole listing is read before anything is
# deleted (deleting while paging would skip some); an expired artifact
# (an earlier attempt's) is already gone.
delete_artifacts() { # [pattern]
    local pattern="${1-*}"
    [ -n "$pattern" ] || fail "delete-artifacts: an empty pattern names no artifact"
    local repo="${GITHUB_REPOSITORY:-}" run="${GITHUB_RUN_ID:-}"
    [[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || fail "delete-artifacts: GITHUB_REPOSITORY $(quoted "$repo") isn't owner/name"
    [[ "$run" =~ ^[0-9]+$ ]] || fail "delete-artifacts: GITHUB_RUN_ID $(quoted "$run") isn't a run id"
    local listing
    listing="$(gh api --paginate "repos/$repo/actions/runs/$run/artifacts" \
        --jq '.artifacts[] | select(.expired | not) | "\(.id)\t\(.name)"')" ||
        fail "delete-artifacts: couldn't list run $run's artifacts"
    local id name deleted=0 kept=0
    while IFS=$'\t' read -r id name; do
        [ -n "$id" ] || continue
        [[ "$id" =~ ^[0-9]+$ ]] || fail "delete-artifacts: artifact id $(quoted "$id")"
        # shellcheck disable=SC2053 # the pattern matches as a pattern
        if [[ "$name" == $pattern ]]; then
            gh api --silent -X DELETE "repos/$repo/actions/artifacts/$id" ||
                fail "delete-artifacts: couldn't delete $(quoted "$name")"
            say "deleted $name"
            deleted=$((deleted + 1))
        else
            kept=$((kept + 1))
        fi
    done <<< "$listing"
    say "deleted $deleted artifact(s) of run $run; kept $kept"
}

step="${1:-}"
shift || true
case "$step" in
    matrix) matrix "${1:?usage: github.sh matrix <work>}" ;;
    build-env) build_env "${1:?usage: github.sh build-env <triple> <file>}" "${2:?usage: github.sh build-env <triple> <file>}" ;;
    signing-toml)
        signing_toml "${1:?usage: github.sh signing-toml <file>}"
        if [ "$signed_unsigned" = 1 ]; then
            export_env SEAWORTHY_UNSIGNED 1
        else
            export_env SEAWORTHY_SIGNING "$signed_file"
        fi
        ;;
    data-path) data_path ;;
    oidc-grant) oidc_grant ;;
    signed) signed "${1:?usage: github.sh signed <step>}" ;;
    apple-cleanup) apple_cleanup ;;
    assemble) assemble "$@" ;;
    delete-artifacts) delete_artifacts "$@" ;;
    *) echo "usage: $0 matrix|build-env|data-path|oidc-grant|signing-toml|signed|apple-cleanup|assemble|delete-artifacts" >&2; exit 2 ;;
esac
