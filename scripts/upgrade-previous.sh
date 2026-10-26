#!/usr/bin/env bash
# scripts/upgrade-previous.sh — the upgrade-from-previous lanes' previous
# build: the artifact <name> (a build scripts/upgrade-candidate.sh wrote)
# of the latest successful run of the lab workflow on `main` before this
# run, fetched through the GitHub API with the job's own token
# (`actions: read`), checked and unpacked into <out>.
#
#   scripts/upgrade-previous.sh <artifact name> <out>
#
# The run: a successful run of SEAWORTHY_UPGRADE_WORKFLOW (default
# lab.yml) on SEAWORTHY_UPGRADE_BRANCH (default main), from a push, the
# schedule or a manual dispatch (never a pull request's: its code isn't
# main's), whose head is this repository's, with a lower run number than
# this run (an older release than this run's candidate), the highest such.
# The artifact: that run's one artifact of that name, not expired, its zip
# no larger than 1 GiB and matching the SHA-256 digest GitHub recorded at
# upload; then every file lab-build.json lists matches its SHA-256, and the
# build's CI test key is the one this checkout's fixture trusts (else this
# candidate isn't one its helper would install).
#
# Exit 0 with <out> filled (<out>/previous-run.json names the run), 3 when
# there is nothing to update from (no such run yet: the lane's first run on
# main, or one whose artifact is gone or predates this lane; or a build that
# trusts another key) — the lane skips with a notice and this run becomes
# the next one's previous build — and 1 on any other error, which fails the
# lane: a broken download or a digest mismatch never skips.
#
# Environment: GITHUB_TOKEN (the job's token; never printed or put on a
# command line), GITHUB_REPOSITORY, GITHUB_RUN_NUMBER, GITHUB_API_URL
# (default https://api.github.com). Needs curl, jq, python3 and sha256sum
# or shasum.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"
name="${1:-}"
out="${2:-}"
[ -n "$name" ] && [ -n "$out" ] || { echo "usage: $0 <artifact name> <out>" >&2; exit 2; }
case "$out" in /*) ;; *) out="$PWD/$out" ;; esac

fail() { echo "upgrade-previous: FAIL: $*" >&2; exit 1; }
none() { echo "upgrade-previous: no previous build: $*" >&2; exit 3; }
say() { echo "upgrade-previous: $*" >&2; }

: "${GITHUB_TOKEN:?the job token (permissions: actions: read)}"
: "${GITHUB_REPOSITORY:?not in GitHub Actions}"
: "${GITHUB_RUN_NUMBER:?not in GitHub Actions}"
api="${GITHUB_API_URL:-https://api.github.com}"
workflow="${SEAWORTHY_UPGRADE_WORKFLOW:-lab.yml}"
branch="${SEAWORTHY_UPGRADE_BRANCH:-main}"
[[ "$name" =~ ^[A-Za-z0-9._-]+$ ]] || fail "artifact name ${name@Q}"
[[ "$workflow" =~ ^[A-Za-z0-9._-]+$ ]] || fail "workflow ${workflow@Q}"
[[ "$branch" =~ ^[A-Za-z0-9._/-]+$ ]] || fail "branch ${branch@Q}"
[[ "$GITHUB_REPOSITORY" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]] || fail "repository ${GITHUB_REPOSITORY@Q}"
[[ "$GITHUB_RUN_NUMBER" =~ ^[0-9]+$ ]] || fail "run number ${GITHUB_RUN_NUMBER@Q}"
for tool in curl jq python3; do
    command -v "$tool" >/dev/null || fail "$tool not found"
done
sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
# The token goes to curl in a header file (never in its arguments, which
# other processes can read). curl sends it to the API host only: a
# redirect to the artifact storage drops it.
( umask 077; printf 'Authorization: Bearer %s\n' "$GITHUB_TOKEN" > "$tmp/auth" )
# https only (redirects too), bounded in time and size.
get() { # <url> <out file>
    curl --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --silent --show-error \
        --retry 3 --retry-delay 2 --connect-timeout 30 --max-time 120 --max-filesize $((16 * 1024 * 1024)) \
        -o "$2" -H @"$tmp/auth" -H 'Accept: application/vnd.github+json' -H 'X-GitHub-Api-Version: 2022-11-28' "$1"
}

get "$api/repos/$GITHUB_REPOSITORY/actions/workflows/$workflow/runs?branch=$branch&status=success&exclude_pull_requests=true&per_page=100" \
    "$tmp/runs.json" || fail "listing $workflow's runs failed"
run="$(jq -r --argjson current "$GITHUB_RUN_NUMBER" --arg repo "$GITHUB_REPOSITORY" --arg branch "$branch" '
    [.workflow_runs[]
     | select(.conclusion == "success" and .head_branch == $branch
              and (.event == "push" or .event == "schedule" or .event == "workflow_dispatch")
              and .head_repository.full_name == $repo and .run_number < $current)]
    | max_by(.run_number) // empty
    | "\(.id) \(.run_number) \(.head_sha)"' "$tmp/runs.json")"
[ -n "$run" ] || none "no successful $workflow run on $branch before run $GITHUB_RUN_NUMBER"
read -r run_id run_number head_sha <<<"$run"
[[ "$run_id" =~ ^[0-9]+$ ]] || fail "run id ${run_id@Q}"
say "the previous build is run $run_number's ($head_sha)"

get "$api/repos/$GITHUB_REPOSITORY/actions/runs/$run_id/artifacts?name=$name&per_page=100" \
    "$tmp/artifacts.json" || fail "listing run $run_number's artifacts failed"
artifact="$(jq -r --arg name "$name" '
    [.artifacts[] | select(.name == $name)] | first // empty
    | "\(.id) \(.expired) \(.size_in_bytes) \(.digest // "")"' "$tmp/artifacts.json")"
[ -n "$artifact" ] || none "run $run_number has no $name artifact (it predates this lane)"
read -r artifact_id expired size digest <<<"$artifact"
[ "$expired" = false ] || none "run $run_number's $name artifact has expired"
[[ "$artifact_id" =~ ^[0-9]+$ ]] || fail "artifact id ${artifact_id@Q}"
[[ "$size" =~ ^[0-9]+$ ]] && [ "$size" -le $((1024 * 1024 * 1024)) ] || fail "the artifact is ${size@Q} bytes (at most 1 GiB)"
[[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || fail "run $run_number's $name artifact has no recorded SHA-256 digest (${digest@Q})"

# The zip, by its id; GitHub answers with a redirect to its storage.
curl --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --silent --show-error --location \
    --retry 3 --retry-delay 2 --connect-timeout 30 --max-time 600 --max-filesize $((1024 * 1024 * 1024)) \
    -o "$tmp/artifact.zip" -H @"$tmp/auth" -H 'Accept: application/vnd.github+json' \
    -H 'X-GitHub-Api-Version: 2022-11-28' \
    "$api/repos/$GITHUB_REPOSITORY/actions/artifacts/$artifact_id/zip" ||
    fail "downloading run $run_number's $name artifact failed"
actual="$(sha256 "$tmp/artifact.zip")"
[ "sha256:$actual" = "$digest" ] || fail "run $run_number's $name artifact is sha256:$actual, but GitHub recorded $digest"
say "the artifact matches its recorded digest ($digest)"

# Unpacked into a new, empty directory (Python's extractor never writes
# outside it), then every listed file checked.
rm -rf "${out:?}"
mkdir -p "$out"
python3 -I -m zipfile -e "$tmp/artifact.zip" "$out"
[ -f "$out/lab-build.json" ] || fail "the artifact holds no lab-build.json"
python3 -I - "$out" <<'PYEOF' || fail "the previous build doesn't match its lab-build.json"
import hashlib, json, os, sys
root = sys.argv[1]
build = json.load(open(os.path.join(root, "lab-build.json")))
if build.get("format") != 1 or not build.get("files"):
    sys.exit("lab-build.json: format 1 with files expected")
for name, digest in build["files"].items():
    path = os.path.normpath(os.path.join(root, name))
    if not path.startswith(root + os.sep) or not os.path.isfile(path):
        sys.exit(f"{name}: listed but missing")
    with open(path, "rb") as f:
        actual = hashlib.sha256(f.read()).hexdigest()
    if actual != digest:
        sys.exit(f"{name}: sha256 {actual}, listed {digest}")
PYEOF
trust="$(jq -r .trust "$out/lab-build.json")"
[ "$trust" = "$(sha256 crates/seaworthy-launcher/e2e/desktop/keys/ci-test.pub)" ] ||
    none "run $run_number's build trusts another CI test key than this checkout's fixture (a key rotation): its helper would refuse this candidate"
jq -n --argjson id "$run_id" --argjson number "$run_number" --arg sha "$head_sha" --arg digest "$digest" \
    '{run_id: $id, run_number: $number, head_sha: $sha, artifact_digest: $digest}' > "$out/previous-run.json"
say "unpacked $(jq -r '"\(.package) \(.token) (sequence \(.sequence))"' "$out/lab-build.json") into $out"
