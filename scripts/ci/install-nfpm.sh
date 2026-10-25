#!/usr/bin/env bash
# scripts/ci/install-nfpm.sh — install the pinned nFPM (goreleaser/nfpm),
# which seaworthy runs to build deb, rpm and pacman packages, without root
# and without a package manager: the release tarball, fetched by its exact
# URL and verified by SHA-256 before anything is extracted. The build is
# reproducible only with this exact version (seaworthy::nfpm::PINNED_VERSION).
#
#   scripts/ci/install-nfpm.sh [<dir>]      # default: target/ci-tools/nfpm
#
# Prints the binary's path; export it as NFPM for seaworthy and its tests.
# A binary already present is reused only when its own SHA-256 matches the
# pin (NFPM_BIN_SHA256), so CI can cache <dir> without trusting the cache:
# a swapped or corrupted binary is fetched again.
#
# Bumping the pin: take the new release's nfpm_<version>_Linux_x86_64.tar.gz
# URL and its line in the release's checksums.txt, update the version, URL
# and tarball hash, run this script once with NFPM_BIN_SHA256 empty to learn
# the binary's hash (it prints it and stops), pin that too, and run
# `cargo test -p seaworthy` with NFPM set: the package tests read
# every format back and check that two builds are identical.
set -euo pipefail

NFPM_VERSION="2.47.0"
NFPM_URL="https://github.com/goreleaser/nfpm/releases/download/v${NFPM_VERSION}/nfpm_${NFPM_VERSION}_Linux_x86_64.tar.gz"
NFPM_SHA256="0660ca602b2d2d2ae4781a06c692b3eeb9d437ffea05b831d76e41f4a3188783"
# `nfpm` inside that tarball.
NFPM_BIN_SHA256="17133a2467ffb7cec851c2d7bae0c6098d09d7ed7d3d101a9605f6a473323936"

top="$(git rev-parse --show-toplevel)" ||
    { echo "install-nfpm: git can't read this checkout (above): run inside it" >&2; exit 1; }
cd "$top"
dir="${1:-target/ci-tools/nfpm}"
case "$dir" in
    /*) ;;
    *) dir="$PWD/$dir" ;;
esac
bin="$dir/nfpm"

die() { echo "install-nfpm: $*" >&2; exit 1; }
hash_of() { sha256sum "$1" | cut -d' ' -f1; }

if [ -x "$bin" ] && [ -n "$NFPM_BIN_SHA256" ] && [ "$(hash_of "$bin")" = "$NFPM_BIN_SHA256" ]; then
    echo "$bin"
    exit 0
fi
[ -e "$bin" ] && echo "install-nfpm: $bin does not match the pinned hash; fetching it again" >&2

command -v curl >/dev/null || die "curl not found"
mkdir -p "$dir"
tarball="$(mktemp "$dir/nfpm.XXXXXX.tar.gz")"
trap 'rm -f "$tarball" "$bin.tmp"' EXIT
echo "install-nfpm: fetching nFPM $NFPM_VERSION" >&2
curl -fsSL --retry 3 --max-time 600 -o "$tarball" "$NFPM_URL" || die "download failed: $NFPM_URL"
actual="$(hash_of "$tarball")"
[ "$actual" = "$NFPM_SHA256" ] || die "SHA-256 mismatch for $NFPM_URL: got $actual, pinned $NFPM_SHA256"
tar -xzf "$tarball" -O nfpm > "$bin.tmp" || die "cannot extract nfpm"
bin_actual="$(hash_of "$bin.tmp")"
if [ -z "$NFPM_BIN_SHA256" ]; then
    die "the extracted nfpm has SHA-256 $bin_actual — pin it as NFPM_BIN_SHA256"
fi
[ "$bin_actual" = "$NFPM_BIN_SHA256" ] || die "SHA-256 mismatch for the extracted nfpm: got $bin_actual, pinned $NFPM_BIN_SHA256"
chmod 0755 "$bin.tmp"
"$bin.tmp" --version 2>/dev/null | grep -qE "GitVersion: +${NFPM_VERSION}\$" || die "the extracted binary does not report $NFPM_VERSION"
mv "$bin.tmp" "$bin"
echo "$bin"
