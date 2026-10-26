#!/usr/bin/env bash
# scripts/upgrade-candidate.sh — the upgrade-from-previous lanes' candidate:
# this checkout's lab fixture, built and packaged as a non-release build
# signed with the CI test key, as the next lab run's previous build will be
# too.
#
#   scripts/upgrade-candidate.sh linux <out>    # the `agent` product: deb, rpm, pacman
#   scripts/upgrade-candidate.sh macos <out>    # the `daemon` product: a pkg (on the Mac)
#
# The product is crates/seaworthy-launcher/e2e/desktop/seaworthy.toml's
# (copied, with this build's version token written into its lab/build.txt,
# so an upgrade shows in the installed files): the launcher and its cores
# as a service, with demo_helper compiled to trust the fixture's CI test key
# and to reach the lab under its names (SEAWORTHY_LAB_*:
# https://updates.lab.invalid/_lab/required-version for its version
# source, https://packages.lab.invalid/repo/releases/... for releases).
# Built through the CI template's build step (on Linux in the pinned
# builder, offline: scripts/lib/lab.sh; on the Mac natively), packaged by
# `seaworthy package --ci-test-signing` (the key copied into a private
# directory first: the CLI signs only with key files no one else can
# read). Into <out>:
#
#   lab-build.json   {"format": 1, "platform", "product", "package",
#                     "version", "sequence", "build", "token", "commit",
#                     "trust": <SHA-256 of the CI test public key>,
#                     "files": {"<path>": "<SHA-256>", ...}}
#   packages.json    the CLI's listing (`ci_test: true`)
#   packages/        the packages and their release manifests
#   bin/conformance_server   (Linux) the lab server, built beside them
#
# The version is the workspace's, the sequence SEAWORTHY_UPGRADE_SEQUENCE
# (CI: the workflow's run number, so a later run is a newer release;
# default 1), the build metadata the commit (`g` and 12 hex digits).
#
# Linux needs docker (an unprivileged builder container), python3 and the
# pinned nFPM (scripts/ci/install-nfpm.sh when NFPM isn't set); the Mac,
# bash 4.4+ and Xcode's command line tools.
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"

cd "$(git rev-parse --show-toplevel)"
platform="${1:-}"
out="${2:-}"
case "$platform" in
    linux) PRODUCT=agent TRIPLE=x86_64-unknown-linux-gnu ;;
    macos) PRODUCT=daemon TRIPLE=aarch64-apple-darwin ;;
    *) echo "usage: $0 <linux|macos> <out>" >&2; exit 2 ;;
esac
[ -n "$out" ] || { echo "usage: $0 <linux|macos> <out>" >&2; exit 2; }
case "$out" in /*) ;; *) out="$PWD/$out" ;; esac

# shellcheck source=scripts/lib/lab.sh
. scripts/lib/lab.sh

fail() { echo "upgrade-candidate: FAIL: $*" >&2; exit 1; }
say() { echo "upgrade-candidate: $*"; }

PRIVATE=""
cleanup() {
    lab_cleanup
    [ -z "$PRIVATE" ] || rm -rf "$PRIVATE"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

TOOL_TARGET="${CARGO_TARGET_DIR:-$PWD/target}"
sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

case "$platform" in
    linux) [ "$(uname -s)-$(uname -m)" = "Linux-x86_64" ] || fail "the Linux candidate builds on x86-64 Linux" ;;
    macos) [ "$(uname -s)-$(uname -m)" = "Darwin-arm64" ] || fail "the macOS candidate builds on Apple Silicon macOS" ;;
esac
command -v python3 >/dev/null || fail "python3 not found"

say "building seaworthy"
CARGO_TARGET_DIR="$TOOL_TARGET" cargo build --quiet --locked -p seaworthy --bin seaworthy
seaworthy() { "$TOOL_TARGET/debug/seaworthy" "$@"; }

# The workspace's version, through a crate that inherits it.
version="$(seaworthy manifest-version --manifest crates/seaworthy-lab/Cargo.toml)"
sequence="${SEAWORTHY_UPGRADE_SEQUENCE:-1}"
[[ "$sequence" =~ ^[1-9][0-9]{0,9}$ ]] || fail "SEAWORTHY_UPGRADE_SEQUENCE ${sequence@Q} isn't a release sequence"
commit="$(git rev-parse --short=12 HEAD)"
build="g$commit"
token="$version+$build"

rm -rf "${out:?}"
mkdir -p "$out/packages" "$out/work"
fixture="$out/work/fixture"
cp -R "$LAB_E2E/desktop" "$fixture"
printf '%s\n' "$token" > "$fixture/lab/build.txt"
config="$fixture/seaworthy.toml"
seaworthy check --config "$config" >/dev/null || fail "the fixture's seaworthy.toml doesn't check"

inputs=(
    "SEAWORTHY_LAB_CONFIG=$config"
    "SEAWORTHY_LAB_RELEASE_PUB=$fixture/keys/ci-test.pub"
    "SEAWORTHY_LAB_PRODUCT=$PRODUCT"
    "SEAWORTHY_LAB_PACKAGE_URL=https://packages.lab.invalid/repo/releases/{product}/{channel}/{version}/{target}/{product}.{format}"
    "SEAWORTHY_LAB_VERSION_URL=https://updates.lab.invalid/_lab/required-version"
)
plan="$out/work/plan-$TRIPLE.tsv"
seaworthy build-plan --config "$config" --triple "$TRIPLE" --product "$PRODUCT" \
    --manifest "$LAB_E2E/Cargo.toml" > "$plan"
artifacts="$out/work/artifacts"
say "building $PRODUCT $token (sequence $sequence) for $TRIPLE"
if [ "$platform" = linux ]; then
    lab_build_linux "$plan" "$artifacts" "$out/bin/conformance_server" "$version" "$build" "${inputs[@]}"
else
    work="$out/work/build"
    mkdir -p "$work"
    cp "$plan" "$work/"
    env "${inputs[@]}" SEAWORTHY_WORK="$work" SEAWORTHY_MANIFEST="$LAB_E2E/Cargo.toml" \
        SEAWORTHY_TARGET_DIR="$TOOL_TARGET/lab-candidate" SEAWORTHY_VERSION="$version" \
        SEAWORTHY_BUILD_COMMAND="printf %s $build" \
        bash scripts/ci/seaworthy.sh build "$TRIPLE"
    mkdir -p "$artifacts"
    cp -R "$work/artifacts/$TRIPLE" "$artifacts/"
fi

# The CI test key, in a private copy: the CLI signs only with key files
# no one else can read (git checks it out 0644).
PRIVATE="$(mktemp -d)"
chmod 700 "$PRIVATE"
cp "$fixture/keys/ci-test.key" "$PRIVATE/ci-test.key"
chmod 600 "$PRIVATE/ci-test.key"
printf '[[manifest]]\nalgorithm = "ml-dsa-87"\nkey = "ci-test.key"\n' > "$PRIVATE/signing.ci-test.toml"
if [ "$platform" = linux ] && [ -z "${NFPM:-}" ]; then
    NFPM="$(scripts/ci/install-nfpm.sh)"
fi
export NFPM="${NFPM:-}"
SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
export SOURCE_DATE_EPOCH
say "packaging $PRODUCT $token (CI test signing)"
seaworthy package --config "$config" --product "$PRODUCT" --platforms "$platform" \
    --artifacts "$artifacts" --out "$out/work/out" --release "$version" --sequence "$sequence" \
    --build "$build" --ci-test-signing "$PRIVATE/signing.ci-test.toml" >/dev/null
cp "$out/work/out/$PRODUCT/packages/"* "$out/packages/"
cp "$out/work/out/$PRODUCT/packages.json" "$out/packages.json"
grep -q '"ci_test": true' "$out/packages.json" || fail "the listing isn't a CI test build's"

package="$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))["package"])' "$out/packages.json")"
trust="$(sha256 "$fixture/keys/ci-test.pub")"
rm -rf "$out/work"
files=()
while IFS= read -r -d '' file; do
    files+=("${file#"$out"/}" "$(sha256 "$file")")
done < <(find "$out/packages.json" "$out/packages" "$out/bin" -type f -print0 2>/dev/null | sort -z)
python3 -I - "$out/lab-build.json" "$platform" "$PRODUCT" "$package" "$version" "$sequence" "$build" \
    "$token" "$commit" "$trust" "${files[@]}" <<'PYEOF'
import json, sys
path, platform, product, package, version, sequence, build, token, commit, trust, *pairs = sys.argv[1:]
files = dict(zip(pairs[0::2], pairs[1::2]))
with open(path, "w") as out:
    json.dump({"format": 1, "platform": platform, "product": product, "package": package,
               "version": version, "sequence": int(sequence), "build": build, "token": token,
               "commit": commit, "trust": trust, "files": files}, out, indent=2, sort_keys=True)
    out.write("\n")
PYEOF
say "built $package $token (sequence $sequence): $(( ${#files[@]} / 2 )) files in $out"
