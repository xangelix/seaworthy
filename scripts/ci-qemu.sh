#!/usr/bin/env bash
# scripts/ci-qemu.sh — install a pinned, static qemu-x86_64 (qemu-user) for
# seaworthy-launcher's emulated-CPU checks (scripts/launcher-e2e.sh), without
# root and without the distro's package manager: Ubuntu 26.04 LTS's
# `qemu-user` package (static binaries), fetched by its exact URL and
# verified by SHA-256 before anything is extracted.
#
# The package is the one in the release pocket (`resolute`, never -updates or
# -security), which is frozen once a release ships, so its URLs only change
# when the pin does: archive.ubuntu.com serves it until 26.04's standard
# support ends (April 2031), and Launchpad keeps its own copy beyond that.
# The pin, not the source, decides what is used.
#
#   scripts/ci-qemu.sh [<dir>]      # default: target/ci-tools/qemu
#   QEMU_X86_64="$(scripts/ci-qemu.sh)" scripts/launcher-e2e.sh
#
# Requirements: bash, git, curl, binutils' ar, tar, zstd, sha256sum
# (coreutils), and network access to archive.ubuntu.com or launchpad.net.
#
# Prints the binary's path. A binary already present is reused only when
# its own SHA-256 matches the pin (QEMU_BIN_SHA256), so CI can cache <dir>
# without trusting the cache: a swapped or corrupted binary is re-fetched.
#
# Bumping the pin: take `qemu-user` from a newer Ubuntu release's release
# pocket. Its SHA256 comes from the signed index: dists/<release>/InRelease
# (verify it with ubuntu-keyring's archive key) names the SHA-256 of
# universe/binary-amd64/Packages.xz, which names the package's. Update the
# version, both URLs (archive.ubuntu.com/ubuntu/pool/universe/q/qemu/ and
# launchpad.net/ubuntu/+archive/primary/+files/) and the package hash, run
# this script once with QEMU_BIN_SHA256 empty to learn the extracted binary's
# hash (it prints it and stops), pin that too, and run
# `SEAWORTHY_LAUNCHER_E2E_REQUIRED=1 scripts/launcher-e2e.sh` on a host whose
# glibc targets baseline x86-64 (qemu-user runs the host's libraries under the
# emulated CPU) — the CPU model names it uses (qemu64, Nehalem, Haswell,
# Icelake-Server) must exist, and the expected cores depend on which CPU
# features qemu's TCG implements.
set -euo pipefail

QEMU_VERSION="1:10.2.1+ds-1ubuntu3"
# The same package, tried in order: Ubuntu's archive, then Launchpad.
QEMU_URLS=(
    "https://archive.ubuntu.com/ubuntu/pool/universe/q/qemu/qemu-user_10.2.1+ds-1ubuntu3_amd64.deb"
    "https://launchpad.net/ubuntu/+archive/primary/+files/qemu-user_10.2.1+ds-1ubuntu3_amd64.deb"
)
QEMU_SHA256="e6bdaac070232a44b8657cad84ac0853d84b7167b55af82370af040291f55bd8"
# usr/bin/qemu-x86_64 inside that package.
QEMU_BIN_SHA256="6b45cdc86de5cad9065a5e86dc765245b1c73e52861cb9df1a17b555aa58c1b1"

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
command -v zstd >/dev/null || die "zstd not found"
mkdir -p "$dir"
deb="$(mktemp "$dir/qemu-user.XXXXXX.deb")"
trap 'rm -f "$deb"' EXIT
fetched=""
for url in "${QEMU_URLS[@]}"; do
    echo "ci-qemu: fetching qemu-user $QEMU_VERSION from $url" >&2
    # https only (redirects too), bounded in time and size; the pin decides.
    if ! curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location --retry 3 \
        --connect-timeout 30 --max-time 600 --max-filesize $((256 * 1024 * 1024)) \
        -o "$deb" "$url"; then
        echo "ci-qemu: download failed: $url" >&2
        continue
    fi
    actual="$(hash_of "$deb")"
    if [ "$actual" != "$QEMU_SHA256" ]; then
        echo "ci-qemu: SHA-256 mismatch for $url: got $actual, pinned $QEMU_SHA256" >&2
        continue
    fi
    fetched="$url"
    break
done
[ -n "$fetched" ] || die "no source served the pinned qemu-user $QEMU_VERSION"
ar p "$deb" data.tar.zst | zstd -dc | tar -x -O ./usr/bin/qemu-x86_64 > "$bin.tmp" || die "cannot extract qemu-x86_64"
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
