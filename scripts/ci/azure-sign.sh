#!/usr/bin/env bash
# scripts/ci/azure-sign.sh — Authenticode with Azure Artifact Signing
# (formerly Trusted Signing), from Linux: an optional command signer
# `signing.toml`'s [authenticode] can run for each Windows binary and MSI.
# seaworthy stamps every binary's version resource before it signs it, so
# signing happens inside `seaworthy package` (and `adopt-msi`), never in a
# Windows job ahead of it.
#
#   [authenticode]
#   command = ["bash", "seaworthy/scripts/azure-sign.sh",
#              "--endpoint", "<region>.codesigning.azure.net",
#              "--account", "<signing account>", "--profile", "<certificate profile>",
#              "{file}"]
#
# The endpoint, account and certificate profile are your Artifact Signing
# resources'; nothing here defaults them. It signs through jsign 7.5 (pinned
# by SHA-256 below; the service's REST API). The credentials come from the
# environment, never a file or a command line: AZURE_TENANT_ID,
# AZURE_CLIENT_ID and AZURE_CLIENT_SECRET (an app registration with the
# "Trusted Signing Certificate Profile Signer" role on the profile), as the
# template's package-secrets wrapper gives them on a release. The client
# secret reaches curl on its standard input, the access token jsign through
# `env:` — neither appears in a process's arguments. Needs bash, curl,
# sha256sum and a Java 11+ runtime (`java`).
#
# jsign timestamps through Microsoft's RFC 3161 service. A transient failure
# (the service's throttling) is retried twice.
set -euo pipefail
JSIGN_VERSION=7.5
JSIGN_SHA256=602a51c3545a6dc4fb99bd2ea7152b26d1345916d0c93ddfbd5936cb735af91c
TIMESTAMP_URL=http://timestamp.acs.microsoft.com

fail() { echo "azure-sign: $*" >&2; exit 1; }

endpoint="" account="" profile="" file=""
while [ $# -gt 0 ]; do
    case "$1" in
        --endpoint) endpoint="${2:-}"; shift 2 ;;
        --account) account="${2:-}"; shift 2 ;;
        --profile) profile="${2:-}"; shift 2 ;;
        --*) fail "unknown option $1" ;;
        *) [ -z "$file" ] || fail "one file at a time"; file="$1"; shift ;;
    esac
done
[ -n "$file" ] && [ -f "$file" ] || fail "usage: azure-sign.sh --endpoint HOST --account NAME --profile NAME FILE"
# Names, not secrets, but they reach a URL and an alias: refuse anything else.
[[ "$endpoint" =~ ^[a-z0-9]+\.codesigning\.azure\.net$ ]] ||
    fail "--endpoint must be a Trusted Signing endpoint host (<region>.codesigning.azure.net), not ${endpoint@Q}"
[[ "$account" =~ ^[A-Za-z0-9-]{3,64}$ ]] || fail "--account must be a Trusted Signing account name"
[[ "$profile" =~ ^[A-Za-z0-9-]{3,64}$ ]] || fail "--profile must be a certificate profile name"
for variable in AZURE_TENANT_ID AZURE_CLIENT_ID AZURE_CLIENT_SECRET; do
    [ -n "${!variable:-}" ] || fail "$variable is unset (the template's package-secrets gives it on a release)"
done
[[ "$AZURE_TENANT_ID" =~ ^[0-9A-Fa-f-]{36}$ ]] || fail "AZURE_TENANT_ID must be the tenant's GUID"
[[ "$AZURE_CLIENT_ID" =~ ^[0-9A-Fa-f-]{36}$ ]] || fail "AZURE_CLIENT_ID must be the app registration's GUID"
command -v java >/dev/null 2>&1 || fail "java not found (jsign needs a Java 11+ runtime)"
command -v curl >/dev/null 2>&1 || fail "curl not found"

# jsign at its pin, beside this script's tools (fetched once a job, in a
# subshell without the client secret).
tools="${SEAWORTHY_AZURE_SIGN_TOOLS:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../tools}"
mkdir -p "$tools"
jar="$tools/jsign-$JSIGN_VERSION.jar"
if [ ! -f "$jar" ] || ! echo "$JSIGN_SHA256  $jar" | sha256sum -c --status -; then
    (
        unset AZURE_CLIENT_SECRET
        tmp="$(mktemp "$tools/jsign.XXXXXX")"
        curl --proto '=https' --tlsv1.2 -fsSL --retry 3 -o "$tmp" \
            "https://github.com/ebourg/jsign/releases/download/$JSIGN_VERSION/jsign-$JSIGN_VERSION.jar" ||
            { rm -f "$tmp"; fail "fetching jsign $JSIGN_VERSION failed"; }
        echo "$JSIGN_SHA256  $tmp" | sha256sum -c --status - ||
            { rm -f "$tmp"; fail "jsign $JSIGN_VERSION: the download's SHA-256 isn't the pinned one"; }
        mv "$tmp" "$jar"
    ) || exit 1
fi

# An access token for Trusted Signing (OAuth 2.0 client credentials).
response="$(printf '%s' "$AZURE_CLIENT_SECRET" | curl --proto '=https' --tlsv1.2 -fsS --retry 3 \
    "https://login.microsoftonline.com/$AZURE_TENANT_ID/oauth2/v2.0/token" \
    --data-urlencode "client_id=$AZURE_CLIENT_ID" \
    --data-urlencode "client_secret@-" \
    --data-urlencode "grant_type=client_credentials" \
    --data-urlencode "scope=https://codesigning.azure.net/.default")" ||
    fail "Microsoft Entra refused the client credentials (AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET)"
[[ "$response" =~ \"access_token\":\"([^\"]+)\" ]] || fail "Microsoft Entra's answer holds no access token"
SEAWORTHY_AZURE_ACCESS_TOKEN="${BASH_REMATCH[1]}"
export SEAWORTHY_AZURE_ACCESS_TOKEN
unset response AZURE_CLIENT_SECRET

# The pause before a retry, in seconds, doubling: 5 unless a test says.
pause="${SEAWORTHY_AZURE_SIGN_RETRY_SECONDS:-5}"
[[ "$pause" =~ ^[0-9]{1,3}$ ]] || fail "SEAWORTHY_AZURE_SIGN_RETRY_SECONDS must be whole seconds"
attempt=1
until java -jar "$jar" --storetype TRUSTEDSIGNING --keystore "$endpoint" \
    --storepass env:SEAWORTHY_AZURE_ACCESS_TOKEN --alias "$account/$profile" \
    --alg SHA-256 --tsaurl "$TIMESTAMP_URL" --tsmode RFC3161 --replace "$file"; do
    [ "$attempt" -lt 3 ] || fail "jsign failed to sign $file $attempt times"
    attempt=$((attempt + 1))
    sleep "$pause"
    pause=$((pause * 2))
done
