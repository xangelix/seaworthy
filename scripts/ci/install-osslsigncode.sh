#!/usr/bin/env bash
# scripts/ci/install-osslsigncode.sh — build the pinned osslsigncode
# (mtrojnar/osslsigncode), which seaworthy's Authenticode signer and its
# tests run, from its source by exact URL and SHA-256, without root.
#
#   scripts/ci/install-osslsigncode.sh [<dir>]   # default: target/ci-tools/osslsigncode
#
# Prints the binary's path; put its directory first on PATH. Arch ships
# osslsigncode only in the AUR, and an AUR helper builds whatever the
# package's head is, as a user with sudo, inside a job holding CI secrets.
# This builds the pinned release instead,
# fresh on every run: a locally built binary has no stable hash to pin, so
# a cache could only be trusted by trusting whoever wrote it.
#
# Needs cmake, a C compiler, and OpenSSL 3 and zlib with their headers
# (official Arch packages: cmake gcc openssl zlib). With OpenSSL 3,
# osslsigncode timestamps through OpenSSL's own HTTP client, so no curl.
#
# The source is GitHub's archive of the release tag: the project publishes
# no source tarball or Linux binary. Its SHA-512 matches the one the AUR
# package pins, checked independently when the pin was set.
#
# Bumping the pin: take the new tag's archive URL, check its SHA-512
# against the AUR PKGBUILD's sha512sums, pin its SHA-256 here, and run
# `cargo test -p seaworthy` with the binary first on PATH and
# SEAWORTHY_REQUIRE_PACKAGE_TOOLS=1.
set -euo pipefail

OSSLSIGNCODE_VERSION="2.14"
OSSLSIGNCODE_URL="https://github.com/mtrojnar/osslsigncode/archive/refs/tags/${OSSLSIGNCODE_VERSION}.tar.gz"
OSSLSIGNCODE_SHA256="0f033fd6069387d2e489fbd2187e62f624764eb8c2758ee94e3e793e5150b5c5"

top="$(git rev-parse --show-toplevel)" ||
    { echo "install-osslsigncode: git can't read this checkout (above): run inside it" >&2; exit 1; }
cd "$top"
dir="${1:-target/ci-tools/osslsigncode}"
case "$dir" in
    /*) ;;
    *) dir="$PWD/$dir" ;;
esac
bin="$dir/osslsigncode"

die() { echo "install-osslsigncode: $*" >&2; exit 1; }

for tool in curl cmake cc; do
    command -v "$tool" >/dev/null || die "$tool not found"
done
mkdir -p "$dir"
work="$(mktemp -d "$dir/build.XXXXXX")"
trap 'rm -rf "$work"' EXIT
echo "install-osslsigncode: fetching osslsigncode $OSSLSIGNCODE_VERSION" >&2
# https only (redirects too), bounded in time and size; the pin decides.
curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location --retry 3 \
    --connect-timeout 30 --max-time 600 --max-filesize $((64 * 1024 * 1024)) \
    -o "$work/source.tar.gz" "$OSSLSIGNCODE_URL" || die "download failed: $OSSLSIGNCODE_URL"
actual="$(sha256sum "$work/source.tar.gz" | cut -d' ' -f1)"
[ "$actual" = "$OSSLSIGNCODE_SHA256" ] \
    || die "SHA-256 mismatch for $OSSLSIGNCODE_URL: got $actual, pinned $OSSLSIGNCODE_SHA256"
tar -xzf "$work/source.tar.gz" -C "$work"
src="$work/osslsigncode-$OSSLSIGNCODE_VERSION"
[ -f "$src/CMakeLists.txt" ] || die "unexpected archive layout"
# No Python: upstream's CTest setup would otherwise configure its test suite
# and start a local HTTP server during the configure step.
cmake -S "$src" -B "$work/build" -DCMAKE_BUILD_TYPE=Release -DPython3_EXECUTABLE=/nonexistent \
    > "$work/configure.log" 2>&1 || { cat "$work/configure.log" >&2; die "configure failed"; }
cmake --build "$work/build" -j "$(nproc)" > "$work/build.log" 2>&1 \
    || { tail -50 "$work/build.log" >&2; die "build failed"; }
"$work/build/osslsigncode" --version 2>/dev/null | grep -q "^osslsigncode ${OSSLSIGNCODE_VERSION}," \
    || die "the built binary does not report $OSSLSIGNCODE_VERSION"
install -m 0755 "$work/build/osslsigncode" "$bin.tmp"
mv "$bin.tmp" "$bin"
echo "$bin"
