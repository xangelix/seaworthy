#!/usr/bin/env bash
# scripts/ci-qemu.sh — install a pinned, static qemu-x86_64 (qemu-user) for
# seaworthy-launcher's emulated-CPU checks (scripts/launcher-e2e.sh), without
# root and without the distro's package manager: Debian 13's `qemu-user`
# package (static binaries), fetched from snapshot.debian.org by its exact
# URL and verified by SHA-256 before anything is extracted.
#
#   scripts/ci-qemu.sh [<dir>]      # default: target/ci-tools/qemu
#   QEMU_X86_64="$(scripts/ci-qemu.sh)" scripts/launcher-e2e.sh
#
# Requirements: bash, git, curl, binutils' ar, tar with xz support,
# sha256sum (coreutils), and network access to snapshot.debian.org.
#
# Prints the binary's path. A binary already present is reused only when
# its own SHA-256 matches the pin (QEMU_BIN_SHA256), so CI can cache <dir>
# without trusting the cache: a swapped or corrupted binary is re-fetched.
#
# Bumping the pin: pick a newer `qemu-user` from Debian stable, take its
# snapshot URL (snapshot.debian.org/mr/binary/qemu-user/<version>/binfiles)
# and the SHA256 from the archive's Packages index, update the version, URL
# and package hash, run this script once with QEMU_BIN_SHA256 empty to learn
# the extracted binary's hash (it prints it and stops), pin that too, and run
# `SEAWORTHY_LAUNCHER_E2E_REQUIRED=1 scripts/launcher-e2e.sh` — the CPU model
# names it uses (qemu64, Nehalem, Haswell, Icelake-Server) must exist.
set -euo pipefail

QEMU_VERSION="1:10.0.13+ds-0+deb13u1"
QEMU_URL="https://snapshot.debian.org/archive/debian/20260905T205002Z/pool/main/q/qemu/qemu-user_10.0.13%2Bds-0%2Bdeb13u1_amd64.deb"
QEMU_SHA256="ca6ede739327a20ae5a3498230c8a3a9a072c586e131bc6bcc1201eb1725e336"
# usr/bin/qemu-x86_64 inside that package.
QEMU_BIN_SHA256="36d35ffe5363bd49bfa9c2b6a048e9fb2e798fea38285a5a45f52d34f9869089"

cd "$(git rev-parse --show-toplevel)"
dir="${1:-target/ci-tools/qemu}"
case "$dir" in /*) ;; *) dir="$PWD/$dir" ;; esac
bin="$dir/qemu-x86_64"

die() { echo "ci-qemu: $*" >&2; exit 1; }
hash_of() { sha256sum "$1" | cut -d' ' -f1; }

if [ -x "$bin" ] && [ -n "$QEMU_BIN_SHA256" ] && [ "$(hash_of "$bin")" = "$QEMU_BIN_SHA256" ]; then
    echo "$bin"
    exit 0
fi
[ -e "$bin" ] && echo "ci-qemu: $bin does not match the pinned hash; fetching it again" >&2

command -v curl >/dev/null || die "curl not found"
command -v ar >/dev/null || die "ar not found (binutils)"
mkdir -p "$dir"
deb="$(mktemp "$dir/qemu-user.XXXXXX.deb")"
trap 'rm -f "$deb"' EXIT
echo "ci-qemu: fetching qemu-user $QEMU_VERSION" >&2
curl -fsSL --retry 3 --max-time 600 -o "$deb" "$QEMU_URL" || die "download failed: $QEMU_URL"
actual="$(hash_of "$deb")"
[ "$actual" = "$QEMU_SHA256" ] || die "SHA-256 mismatch for $QEMU_URL: got $actual, pinned $QEMU_SHA256"
ar p "$deb" data.tar.xz | tar -xJ -O ./usr/bin/qemu-x86_64 > "$bin.tmp" || die "cannot extract qemu-x86_64"
bin_actual="$(hash_of "$bin.tmp")"
if [ -z "$QEMU_BIN_SHA256" ]; then
    rm -f "$bin.tmp"
    die "extracted qemu-x86_64 has SHA-256 $bin_actual — pin it as QEMU_BIN_SHA256"
fi
[ "$bin_actual" = "$QEMU_BIN_SHA256" ] || die "SHA-256 mismatch for the extracted qemu-x86_64: got $bin_actual, pinned $QEMU_BIN_SHA256"
chmod 0755 "$bin.tmp"
"$bin.tmp" --version | grep -q "${QEMU_VERSION#1:}" || die "the extracted binary does not report $QEMU_VERSION"
mv "$bin.tmp" "$bin"
echo "$bin"
