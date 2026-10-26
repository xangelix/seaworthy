#!/usr/bin/env bash
# Assemble the release archives of the `seaworthy` CLI and their checksums
# (.github/workflows/release.yml, docs/releasing.md).
#
#   scripts/ci/package-release.sh <version> <bins-dir> <out-dir>
#
# <bins-dir> holds one directory per target, `bin-<target>/`, each with the
# built `seaworthy` (or `seaworthy.exe`) binary. For every target this writes
# `seaworthy-<version>-<target>.tar.gz` (`.zip` for Windows) into <out-dir>,
# holding `seaworthy-<version>-<target>/` with the binary, both licenses and
# the README, and then `SHA256SUMS` over the archives.
#
# The archives are deterministic for given inputs: entries sorted, owner and
# group 0, modes normalized (0755 directories and programs, 0644 the rest,
# whatever the caller's umask), every timestamp set to SOURCE_DATE_EPOCH
# (default: the commit time of HEAD), gzip without a name or time stamp, zip
# entries written by Python's zipfile with fixed times and modes. Needs GNU
# tar, gzip, python3 and sha256sum (GitHub's Ubuntu runners have them).
set -euo pipefail
umask 022

die() { echo "package-release: $*" >&2; exit 2; }

[ "$#" -eq 3 ] || die "usage: scripts/ci/package-release.sh <version> <bins-dir> <out-dir>"
version="$1"
bins="$(cd "$2" && pwd)" || die "no such directory: $2"
out="$3"

[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || die "not a version: $version"
for tool in tar gzip python3 sha256sum; do
    command -v "$tool" >/dev/null || die "$tool not found"
done
tar --version 2>/dev/null | grep -q 'GNU tar' || die "GNU tar is required"

root="$(git rev-parse --show-toplevel)"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "$root" log -1 --format=%ct)}"
[[ "$SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ]] || die "SOURCE_DATE_EPOCH must be a Unix time"
export TZ=UTC LC_ALL=C

mkdir -p "$out"
out="$(cd "$out" && pwd)"
[ -z "$(ls -A "$out")" ] || die "$out is not empty"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# write_zip <base dir> <top-level name> <zip path>: the tree under
# <base>/<name>, files only, sorted, every entry dated SOURCE_DATE_EPOCH.
write_zip() {
    python3 -I - "$@" <<'PY'
import os, sys, time, zipfile
base, name, path = sys.argv[1:4]
stamp = time.gmtime(int(os.environ["SOURCE_DATE_EPOCH"]))[:6]
stamp = max(stamp, (1980, 1, 1, 0, 0, 0))
files = []
for parent, _, names in os.walk(os.path.join(base, name)):
    files += [os.path.join(parent, n) for n in names]
with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
    for full in sorted(files):
        entry = zipfile.ZipInfo(os.path.relpath(full, base).replace(os.sep, "/"), stamp)
        mode = 0o755 if os.access(full, os.X_OK) else 0o644
        entry.external_attr = (0o100000 | mode) << 16
        entry.create_system = 3
        entry.compress_type = zipfile.ZIP_DEFLATED
        with open(full, "rb") as fp:
            archive.writestr(entry, fp.read())
PY
}

count=0
for dir in "$bins"/bin-*/; do
    [ -d "$dir" ] || continue
    target="$(basename "$dir")"
    target="${target#bin-}"
    [[ "$target" =~ ^[a-z0-9_]+(-[a-z0-9_]+){2,3}$ ]] || die "not a target triple: $target"
    case "$target" in
        *-windows-*) exe="seaworthy.exe" ;;
        *) exe="seaworthy" ;;
    esac
    [ -f "$dir/$exe" ] || die "$dir has no $exe"

    name="seaworthy-$version-$target"
    stage="$work/$name"
    install -d -m 0755 "$stage"
    install -m 0755 "$dir/$exe" "$stage/$exe"
    for doc in LICENSE-APACHE LICENSE-MIT README.md; do
        install -m 0644 "$root/$doc" "$stage/$doc"
    done
    find "$stage" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +

    case "$target" in
        *-windows-*)
            write_zip "$work" "$name" "$out/$name.zip"
            ;;
        *)
            tar --sort=name --format=gnu --owner=0 --group=0 --numeric-owner \
                --mtime="@$SOURCE_DATE_EPOCH" --mode='u=rwX,go=rX' \
                -C "$work" -cf - "$name" | gzip -n -9 >"$out/$name.tar.gz"
            ;;
    esac
    count=$((count + 1))
done

[ "$count" -gt 0 ] || die "no bin-<target>/ directories in $bins"

(cd "$out" && find . -maxdepth 1 -type f -printf '%f\n' | sort | xargs sha256sum >"$work/SHA256SUMS")
mv "$work/SHA256SUMS" "$out/SHA256SUMS"
echo "package-release: $count archives in $out" >&2
cat "$out/SHA256SUMS"
