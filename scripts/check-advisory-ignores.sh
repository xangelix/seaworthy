#!/usr/bin/env bash
# scripts/check-advisory-ignores.sh — osv-scanner.toml excepts exactly the
# advisories deny.toml's [advisories] ignore list does, and every entry of
# osv-scanner.toml carries a reason and an expiry. cargo-deny is the gate
# (an ignore that matches nothing fails it); osv-scanner.toml only keeps
# OpenSSF Scorecard's Vulnerabilities check from reporting an advisory
# deny.toml already accepts, and nothing else would notice it outliving the
# deny.toml entry it copies. An osv-scanner.toml entry whose reason starts
# with "lockfile only:" is the exception: a crate the lockfile holds that no
# build compiles, which cargo-deny never meets and so deny.toml cannot list.
#
#   scripts/check-advisory-ignores.sh
set -euo pipefail
cd "$(dirname "$0")/.."

# The IDs in deny.toml's [advisories] ignore = [ ... ] array.
deny_ids="$(awk '
    /^\[/ { section = $0 }
    section == "[advisories]" && /^ignore[[:space:]]*=[[:space:]]*\[/ { inside = 1 }
    inside { print }
    inside && /^\]/ { inside = 0 }
' deny.toml | sed -n 's/.*id[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' | sort)"

# The IDs of osv-scanner.toml's [[IgnoredVulns]] tables, without the
# "lockfile only:" ones.
osv_ids="$(awk '
    /^\[\[IgnoredVulns\]\]/ { if (id != "" && !lockfile_only) print id; id = ""; lockfile_only = 0 }
    /^id[[:space:]]*=/ { id = $0; sub(/^id[[:space:]]*=[[:space:]]*"/, "", id); sub(/".*/, "", id) }
    /^reason[[:space:]]*=[[:space:]]*"lockfile only:/ { lockfile_only = 1 }
    END { if (id != "" && !lockfile_only) print id }
' osv-scanner.toml | sort)"
lockfile_only="$(grep -c '^reason[[:space:]]*=[[:space:]]*"lockfile only:' osv-scanner.toml || true)"

status=0
if [ "$deny_ids" != "$osv_ids" ]; then
    echo "check-advisory-ignores: deny.toml and osv-scanner.toml except different advisories" >&2
    { diff <(printf '%s\n' "$deny_ids") <(printf '%s\n' "$osv_ids") || true; } |
        sed -n 's/^</  deny.toml only:/p; s/^>/  osv-scanner.toml only:/p' >&2
    status=1
fi

entries="$(grep -c '^\[\[IgnoredVulns\]\]' osv-scanner.toml || true)"
for field in id reason ignoreUntil; do
    count="$(grep -c "^${field}[[:space:]]*=" osv-scanner.toml || true)"
    if [ "$count" != "$entries" ]; then
        echo "check-advisory-ignores: $entries osv-scanner.toml entries, $count with $field" >&2
        status=1
    fi
done

if [ "$status" = 0 ]; then
    echo "check-advisory-ignores: deny.toml and osv-scanner.toml except the same $((entries - lockfile_only)) advisories; osv-scanner.toml also $lockfile_only lockfile-only"
fi
exit "$status"
