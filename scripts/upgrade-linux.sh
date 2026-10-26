#!/usr/bin/env bash
# scripts/upgrade-linux.sh — the upgrade-from-previous lane on Linux: the
# previous build (scripts/upgrade-previous.sh) installed on Debian 13,
# Ubuntu 24.04, UBI 9, Fedora 43 and Arch, then updated to the candidate
# (scripts/upgrade-candidate.sh linux) by its own update helper against the
# lab server, the transition asserted: crates/seaworthy-lab/tests/
# upgrade_linux.rs, which documents every step.
#
#   scripts/upgrade-linux.sh <previous> <candidate> [<report dir>]
#
# CI only (the lab workflow's Linux upgrade job): it boots systemd hosts
# with CAP_SYS_ADMIN (never privileged) on the job's own docker daemon.
# SEAWORTHY_TEST_CONTAINERS_REQUIRED=1 turns a missing daemon into a
# failure.
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"

cd "$(git rev-parse --show-toplevel)"
previous="${1:-}"
candidate="${2:-}"
report="${3:-$PWD/target/lab-upgrade/report}"
[ -n "$previous" ] && [ -n "$candidate" ] || { echo "usage: $0 <previous> <candidate> [<report dir>]" >&2; exit 2; }
fail() { echo "upgrade-linux: FAIL: $*" >&2; exit 1; }
abs() { case "$1" in /*) echo "$1" ;; *) echo "$PWD/$1" ;; esac; }
previous="$(abs "$previous")" candidate="$(abs "$candidate")" report="$(abs "$report")"
for dir in "$previous" "$candidate"; do
    [ -f "$dir/lab-build.json" ] || fail "$dir has no lab-build.json"
done
[ -x "$candidate/bin/conformance_server" ] || chmod 0755 "$candidate/bin/conformance_server" 2>/dev/null ||
    fail "the candidate has no lab server (bin/conformance_server)"
rm -rf "$report"
SEAWORTHY_UPGRADE_PREVIOUS="$previous" SEAWORTHY_UPGRADE_CANDIDATE="$candidate" SEAWORTHY_UPGRADE_REPORT="$report" \
    cargo test --locked -p seaworthy-lab --features upgrade --test upgrade_linux --no-fail-fast \
    -- --test-threads "${SEAWORTHY_UPGRADE_THREADS:-3}"
for distro in debian-13 ubuntu-24.04 ubi-9 fedora-43 arch; do
    [ -f "$report/$distro.json" ] || fail "no $report/$distro.json: the lane didn't run on $distro"
done
echo "upgrade-linux: $(jq -r '"\(.previous) -> \(.candidate)"' "$report/debian-13.json") on debian-13, ubuntu-24.04, ubi-9, fedora-43 and arch"
