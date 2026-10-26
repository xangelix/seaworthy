#!/usr/bin/env bash
# scripts/check-lockfiles.sh — every tracked Cargo.lock matches its
# manifests. The repository holds three workspaces (the root, fuzz/ and the
# launcher's e2e fixture, crates/seaworthy-launcher/e2e/); the two nested
# ones reach the root's crates by path, so a dependency bump in the root
# changes what their lockfiles must say. Dependabot watches the root and
# fuzz/ only, and a stale fixture lockfile otherwise fails no earlier than
# the lab's launcher lanes (`--locked` refuses to update it). The fix is
# `cargo update -w` in the directory named (no other crate moves).
#
#   scripts/check-lockfiles.sh
set -euo pipefail
cd "$(dirname "$0")/.."

status=0
while IFS= read -r lock; do
    dir="$(dirname "$lock")"
    if ! out="$(cargo metadata --locked --format-version 1 --manifest-path "$dir/Cargo.toml" 2>&1 >/dev/null)"; then
        echo "check-lockfiles: $lock is out of date: run \`cargo update -w\` in $dir" >&2
        printf '%s\n' "$out" | tail -n 3 >&2
        status=1
    fi
done < <(git ls-files -- '*Cargo.lock' 'Cargo.lock')
[ "$status" = 0 ] && echo "check-lockfiles: every tracked Cargo.lock is current"
exit "$status"
