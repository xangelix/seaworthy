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
# environment, never a command line: AZURE_TENANT_ID and AZURE_CLIENT_ID
# (an app registration, or a user-assigned managed identity, with the
# "Trusted Signing Certificate Profile Signer" role on the profile), and
# one of:
#
#   AZURE_CLIENT_SECRET          the registration's client secret, as the
#                                GitLab template's package-secrets wrapper
#                                gives it on a release;
#   AZURE_FEDERATED_TOKEN_FILE   a file holding a federated identity token
#                                the registration trusts (workload identity
#                                federation: no stored secret);
#   ACTIONS_ID_TOKEN_REQUEST_URL and ACTIONS_ID_TOKEN_REQUEST_TOKEN
#                                GitHub Actions' OIDC (a job with
#                                `id-token: write`): a fresh token for the
#                                audience api://AzureADTokenExchange per
#                                signature, which the registration's
#                                federated credential for the workflow's
#                                repository and environment must trust.
#
# The secret, the federated token and the GitHub request token reach curl
# on its standard input, the access token jsign through `env:` — none
# appears in a process's arguments. Needs bash, curl, sha256sum and a Java
# 11+ runtime (`java`).
#
# jsign timestamps through Microsoft's RFC 3161 service. A transient failure
# (the service's throttling) is retried twice.
set -euo pipefail
JSIGN_VERSION=7.5
JSIGN_SHA256=602a51c3545a6dc4fb99bd2ea7152b26d1345916d0c93ddfbd5936cb735af91c
# Plain http, as Microsoft publishes the endpoint, and acceptable: an RFC 3161
# answer is a timestamp token signed by the timestamp authority, which
# Authenticode verification checks up to its trust anchor (seaworthy checks
# every signature, timestamp included, against [defaults.authenticode]'s
# `trust` after signing). Tampering in transit makes the token fail that
# check; it can't forge one. The request carries only the signature's
# digest, nothing secret.
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
for variable in AZURE_TENANT_ID AZURE_CLIENT_ID; do
    [ -n "${!variable:-}" ] || fail "$variable is unset (the template's package-secrets gives it on a release)"
done
# How this run proves its identity to Microsoft Entra: a client secret, a
# federated token file, or GitHub Actions' OIDC (in that order).
if [ -n "${AZURE_CLIENT_SECRET:-}" ]; then
    credential=secret
elif [ -n "${AZURE_FEDERATED_TOKEN_FILE:-}" ]; then
    [ -f "$AZURE_FEDERATED_TOKEN_FILE" ] || fail "AZURE_FEDERATED_TOKEN_FILE names no file: ${AZURE_FEDERATED_TOKEN_FILE@Q}"
    credential=federated-file
elif [ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" ] && [ -n "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ]; then
    [[ "$ACTIONS_ID_TOKEN_REQUEST_URL" =~ ^https:// ]] || fail "ACTIONS_ID_TOKEN_REQUEST_URL isn't https"
    credential=github-oidc
else
    fail "AZURE_CLIENT_SECRET is unset, and there is no federated credential (AZURE_FEDERATED_TOKEN_FILE, or GitHub Actions' OIDC: a job with id-token: write)"
fi
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
        unset AZURE_CLIENT_SECRET ACTIONS_ID_TOKEN_REQUEST_TOKEN AZURE_FEDERATED_TOKEN_FILE
        tmp="$(mktemp "$tools/jsign.XXXXXX")"
        curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --connect-timeout 30 --max-time 600 \
            --max-filesize $((64 * 1024 * 1024)) -o "$tmp" \
            "https://github.com/ebourg/jsign/releases/download/$JSIGN_VERSION/jsign-$JSIGN_VERSION.jar" ||
            { rm -f "$tmp"; fail "fetching jsign $JSIGN_VERSION failed"; }
        echo "$JSIGN_SHA256  $tmp" | sha256sum -c --status - ||
            { rm -f "$tmp"; fail "jsign $JSIGN_VERSION: the download's SHA-256 isn't the pinned one"; }
        mv "$tmp" "$jar"
    ) || exit 1
fi

# An access token for Trusted Signing (OAuth 2.0 client credentials: the
# client secret, or a federated token as the client assertion).
entra=(curl --proto '=https' --tlsv1.2 -fsS --retry 3
    --connect-timeout 30 --max-time 120 --max-filesize $((1024 * 1024))
    "https://login.microsoftonline.com/$AZURE_TENANT_ID/oauth2/v2.0/token"
    --data-urlencode "client_id=$AZURE_CLIENT_ID"
    --data-urlencode "grant_type=client_credentials"
    --data-urlencode "scope=https://codesigning.azure.net/.default")
case "$credential" in
    secret)
        response="$(printf '%s' "$AZURE_CLIENT_SECRET" | "${entra[@]}" --data-urlencode "client_secret@-")" ||
            fail "Microsoft Entra refused the client credentials (AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET)"
        ;;
    federated-file | github-oidc)
        if [ "$credential" = federated-file ]; then
            assertion="$(tr -d '[:space:]' < "$AZURE_FEDERATED_TOKEN_FILE")"
        else
            # A fresh token per signature (GitHub's last minutes): the
            # request token goes to curl in a config on its standard input.
            separator='?'
            [[ "$ACTIONS_ID_TOKEN_REQUEST_URL" == *\?* ]] && separator='&'
            oidc="$(printf 'header = "Authorization: bearer %s"\n' "$ACTIONS_ID_TOKEN_REQUEST_TOKEN" |
                curl --proto '=https' --tlsv1.2 -fsS --retry 3 --config - \
                    --connect-timeout 30 --max-time 120 --max-filesize $((1024 * 1024)) \
                    "${ACTIONS_ID_TOKEN_REQUEST_URL}${separator}audience=api%3A%2F%2FAzureADTokenExchange")" ||
                fail "GitHub Actions refused an OIDC token (does the job have id-token: write?)"
            [[ "$oidc" =~ \"value\":\"([^\"]+)\" ]] || fail "GitHub Actions' OIDC answer holds no token"
            assertion="${BASH_REMATCH[1]}"
            unset oidc
        fi
        [[ "$assertion" =~ ^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$ ]] ||
            fail "the federated token isn't a JWT"
        response="$(printf '%s' "$assertion" | "${entra[@]}" \
            --data-urlencode "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
            --data-urlencode "client_assertion@-")" ||
            fail "Microsoft Entra refused the federated credential (AZURE_TENANT_ID, AZURE_CLIENT_ID, and the registration's federated credential for this workflow)"
        unset assertion
        ;;
esac
[[ "$response" =~ \"access_token\":\"([^\"]+)\" ]] || fail "Microsoft Entra's answer holds no access token"
SEAWORTHY_AZURE_ACCESS_TOKEN="${BASH_REMATCH[1]}"
export SEAWORTHY_AZURE_ACCESS_TOKEN
unset response AZURE_CLIENT_SECRET ACTIONS_ID_TOKEN_REQUEST_TOKEN AZURE_FEDERATED_TOKEN_FILE

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
