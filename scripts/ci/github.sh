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
#   github.sh signing-toml <file>        signing.toml from the secrets the
#                                        job was handed (names, never values);
#                                        exports SEAWORTHY_SIGNING, or
#                                        SEAWORTHY_UNSIGNED=1 without a signer
#   github.sh apple-keychain             macOS: a throwaway keychain with the
#                                        Developer ID identities and the
#                                        notary profile
#   github.sh apple-cleanup              macOS: that keychain deleted
#   github.sh assemble <out> <label>=<dir>...
#                                        every listed artifact, checked
#                                        against its listing's SHA-256, into
#                                        <out>/<label>/, with SHA256SUMS
#
# Environment (the workflow sets it; the secrets only on a release or a
# dev build, and only in the jobs that sign):
#
#   SEAWORTHY_PLATFORMS                 matrix: linux, windows, macos (comma)
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
#
# Every value that reaches a file is checked first; secrets go to files
# only under a private directory (umask 077) and are never printed.
set -euo pipefail
shopt -s inherit_errexit

fail() { echo "seaworthy (github): FAIL: $*" >&2; exit 1; }
say() { echo "seaworthy (github): $*"; }

# Appends `name=value` to $GITHUB_OUTPUT (or prints it outside Actions).
output() { # <name> <value>
    if [ -n "${GITHUB_OUTPUT:-}" ]; then
        printf '%s=%s\n' "$1" "$2" >> "$GITHUB_OUTPUT"
    else
        printf '%s=%s\n' "$1" "$2"
    fi
}

# Exports `name=value` to the job's later steps ($GITHUB_ENV), or prints it.
export_env() { # <name> <value>
    [[ "$2" != *$'\n'* ]] || fail "$1 holds a newline"
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
    local unknown
    unknown="$(tr ',' '\n' <<<"$platforms" | grep -v -x -E '|linux|windows|macos' || true)"
    [ -z "$unknown" ] || fail "platforms: unknown platform(s) $(tr '\n' ' ' <<<"$unknown")(linux, windows, macos)"
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
            *) fail "build-env: ${key@Q} is neither \"*\" nor a target seaworthy builds" ;;
        esac
    done <<<"$keys"
    jq -e '[.[][] | test("[\\x00-\\x1f\\x7f]")] | any | not' >/dev/null <<<"$json" ||
        fail "build-env: a value holds a control character (a newline, a tab)"
    local name value count=0
    # Name and value NUL-separated, the triple's own after "*" (so they win).
    while IFS= read -r -d '' name && IFS= read -r -d '' value; do
        [[ "$name" =~ ^[A-Za-z_][A-Za-z0-9_]{0,127}$ ]] || fail "build-env: ${name@Q} isn't a variable name"
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
            *) fail "release-manifest-algorithm ${algorithm@Q}: ml-dsa-87, ecdsa-p256 or ed25519" ;;
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
        [ -f "$scripts/azure-sign.sh" ] || fail "no azure-sign.sh in ${scripts@Q}"
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
    # For the later steps: the file, or (no signer at all) an unsigned build.
    if [ "${#sections[@]}" -eq 0 ]; then
        say "signing.toml: no signer was handed to this job: an unsigned build"
        export_env SEAWORTHY_UNSIGNED 1
    else
        say "signing.toml: ${sections[*]}"
        export_env SEAWORTHY_SIGNING "$file"
    fi
}

# macOS: the Developer ID identities imported into a keychain of their own
# (a random password, locked after six hours), first in the search list,
# and the notary service's API key stored as a notarytool profile in it.
# Exports the identities' names, the keychain and the profile for
# signing-toml.
apple_keychain() {
    [ "$(uname -s)" = Darwin ] || fail "apple-keychain runs on macOS"
    [ -n "${SEAWORTHY_GH_APPLE_P12:-}" ] || fail "no APPLE_CERTIFICATE_P12 secret"
    for variable in SEAWORTHY_GH_APPLE_NOTARY_KEY SEAWORTHY_GH_APPLE_NOTARY_KEY_ID SEAWORTHY_GH_APPLE_NOTARY_ISSUER; do
        [ -n "${!variable:-}" ] || fail "Developer ID signing notarizes: the APPLE_NOTARY_KEY, APPLE_NOTARY_KEY_ID and APPLE_NOTARY_ISSUER secrets are required"
    done
    [[ "$SEAWORTHY_GH_APPLE_NOTARY_KEY_ID" =~ ^[A-Z0-9]{6,20}$ ]] || fail "APPLE_NOTARY_KEY_ID isn't an App Store Connect key id"
    [[ "$SEAWORTHY_GH_APPLE_NOTARY_ISSUER" =~ ^[0-9a-fA-F-]{36}$ ]] || fail "APPLE_NOTARY_ISSUER isn't an issuer id (a UUID)"
    local temp="${RUNNER_TEMP:?RUNNER_TEMP is unset}/seaworthy-apple"
    umask 077
    mkdir -p "$temp"
    local keychain="$temp/signing.keychain-db" password profile=seaworthy-notary
    password="$(openssl rand -hex 24)"
    echo "::add-mask::$password"
    security create-keychain -p "$password" "$keychain"
    security set-keychain-settings -lut 21600 "$keychain"
    security unlock-keychain -p "$password" "$keychain"
    base64 -d > "$temp/identity.p12" <<<"$SEAWORTHY_GH_APPLE_P12" || fail "APPLE_CERTIFICATE_P12 isn't base64"
    security import "$temp/identity.p12" -k "$keychain" -f pkcs12 \
        -P "${SEAWORTHY_GH_APPLE_P12_PASSWORD:-}" -T /usr/bin/codesign -T /usr/bin/productbuild >/dev/null ||
        fail "APPLE_CERTIFICATE_P12 doesn't import with APPLE_CERTIFICATE_PASSWORD"
    rm -f "$temp/identity.p12"
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
    rm -f "$temp/AuthKey.p8"
    local identity="${SEAWORTHY_GH_APPLE_IDENTITY:-}" installer=""
    if [ -z "$identity" ]; then
        identity="$(security find-identity -v -p codesigning "$keychain" |
            sed -n 's/^ *[0-9][0-9]*) [0-9A-F]\{40\} "\(Developer ID Application: .*\)"$/\1/p' | head -n1)"
        [ -n "$identity" ] || fail "APPLE_CERTIFICATE_P12 holds no Developer ID Application identity"
    fi
    installer="$(security find-identity -v "$keychain" |
        sed -n 's/^ *[0-9][0-9]*) [0-9A-F]\{40\} "\(Developer ID Installer: .*\)"$/\1/p' | head -n1)"
    export_env SEAWORTHY_GH_APPLE_IDENTITY "$identity"
    export_env SEAWORTHY_GH_APPLE_INSTALLER_IDENTITY "$installer"
    export_env SEAWORTHY_GH_APPLE_KEYCHAIN "$keychain"
    export_env SEAWORTHY_GH_APPLE_NOTARY_PROFILE "$profile"
    say "Developer ID: $identity${installer:+; installer: $installer}"
}

apple_cleanup() {
    local keychain="${RUNNER_TEMP:-}/seaworthy-apple/signing.keychain-db"
    [ -f "$keychain" ] || return 0
    security delete-keychain "$keychain" || true
    say "the signing keychain is deleted"
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
        [[ "$label" =~ ^[a-z0-9-]+$ ]] || fail "assemble: ${label@Q} isn't a label"
        [ -d "$dir" ] || { say "assemble: no $dir ($label): nothing from it"; continue; }
        for listing in "$dir"/*/packages.json; do
            [ -f "$listing" ] || continue
            product="$(basename "$(dirname "$listing")")"
            mkdir -p "$out/$label/$product"
            cp "$listing" "$out/$label/$product/packages.json"
            local file sha actual
            while IFS=$'\t' read -r file sha; do
                [[ "$file" =~ ^[A-Za-z0-9._+~-]+(/[A-Za-z0-9._+~-]+)*$ && "$file" != *..* ]] ||
                    fail "$listing lists ${file@Q}, not a plain relative path"
                [[ "$sha" =~ ^[0-9a-f]{64}$ ]] || fail "$listing: ${file}'s SHA-256 isn't one"
                local from to
                from="$(dirname "$listing")/$file" to="$out/$label/$product/$file"
                [ -f "$from" ] && [ ! -L "$from" ] || fail "$listing lists $file, which isn't there"
                mkdir -p "$(dirname "$to")"
                cp "$from" "$to"
                actual="$(sha256sum "$to" | cut -d' ' -f1)"
                [ "$actual" = "$sha" ] || fail "$label/$product/$file: SHA-256 $actual, but the listing says $sha"
                files=$((files + 1))
            done < <(jq -r '.artifacts[] | [.file, .sha256] | @tsv' "$listing")
        done
    done
    [ "$files" -gt 0 ] || fail "assemble: no listed artifact anywhere"
    local sums
    sums="$(cd "$out" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sed 's#  \./#  #')"
    printf '%s\n' "$sums" > "$out/SHA256SUMS"
    say "assembled $files artifact(s) into $out, checked against their listings (SHA256SUMS)"
}

step="${1:-}"
shift || true
case "$step" in
    matrix) matrix "${1:?usage: github.sh matrix <work>}" ;;
    build-env) build_env "${1:?usage: github.sh build-env <triple> <file>}" "${2:?usage: github.sh build-env <triple> <file>}" ;;
    signing-toml) signing_toml "${1:?usage: github.sh signing-toml <file>}" ;;
    apple-keychain) apple_keychain ;;
    apple-cleanup) apple_cleanup ;;
    assemble) assemble "$@" ;;
    *) echo "usage: $0 matrix|build-env|signing-toml|apple-keychain|apple-cleanup|assemble" >&2; exit 2 ;;
esac
