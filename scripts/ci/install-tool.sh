#!/usr/bin/env bash
# Install a pinned release binary of a CI tool, verified against the SHA-256
# recorded below before anything is unpacked.
#
#   scripts/ci/install-tool.sh <tool> [<tool>...]
#   scripts/ci/install-tool.sh --list
#
# Tools: cargo-deny, cargo-fuzz, actionlint, zizmor, shellcheck.
#
# The binaries land in $SEAWORTHY_TOOLS_DIR (default: $RUNNER_TEMP/seaworthy-tools
# on GitHub Actions, target/tools elsewhere). On GitHub Actions the directory
# is appended to $GITHUB_PATH, so later steps find the tools by name. A tool
# already there is kept only when its own SHA-256 is the pinned binary's
# (the directory may be a cache: a swapped binary is fetched again), and a
# freshly unpacked one must match that pin too.
#
# Why not `cargo install` or a third-party installer action: a release binary
# whose digest is pinned in this file is the same bytes on every run, needs
# no compiler, and trusts nothing beyond the tool's own published release.
#
# Bumping a tool: change its version, URLs and digests together. Take each
# archive digest from the release's published checksum (a `.sha256` file, a
# checksums list, or the asset digest GitHub shows on the release page),
# download the asset, and check that `sha256sum` agrees; then pin the
# SHA-256 of the binary inside it (sha256sum of the unpacked member).
#
# Exit status: 0 = installed, 1 = download or verification failure,
# 2 = usage error or unsupported platform.
set -euo pipefail

die() { echo "install-tool: $1" >&2; exit "${2:-1}"; }

# ---- pins ------------------------------------------------------------------
# One line per tool and platform:
#   <tool> <platform> <version> <archive sha256> <url> <path of the binary inside the archive> <binary sha256>

PINS="
cargo-deny x86_64-linux 0.20.2 9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f https://github.com/EmbarkStudios/cargo-deny/releases/download/0.20.2/cargo-deny-0.20.2-x86_64-unknown-linux-musl.tar.gz cargo-deny-0.20.2-x86_64-unknown-linux-musl/cargo-deny b329e25933d01c36dd7c47d84ea5716694f9b7caf53a5003d45674703a8ed54a
cargo-deny aarch64-linux 0.20.2 995c82be0defc7a025cae49a2aa2644ce8245c9a3318fc4103907c6a285e8c7d https://github.com/EmbarkStudios/cargo-deny/releases/download/0.20.2/cargo-deny-0.20.2-aarch64-unknown-linux-musl.tar.gz cargo-deny-0.20.2-aarch64-unknown-linux-musl/cargo-deny 21e797104e371854dde7f05f52d834e70312749d361c168429ced996f2194462
cargo-fuzz x86_64-linux 0.13.2 b5b704018b63e0f151c17a057ac53b5111e1db545d1b9f72fee79f08a545931c https://github.com/rust-fuzz/cargo-fuzz/releases/download/0.13.2/cargo-fuzz-0.13.2-x86_64-unknown-linux-musl.tar.gz cargo-fuzz f87d63fc80e4f897a32ead5df85bd67665afb6a63ed92bb0d2b0473e15295eba
actionlint x86_64-linux 1.7.12 8aca8db96f1b94770f1b0d72b6dddcb1ebb8123cb3712530b08cc387b349a3d8 https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_amd64.tar.gz actionlint c872d6db8c6bf83a8eaa704fc93999f027d55dffbc63b8a6abdccb47df5f4cd4
actionlint aarch64-linux 1.7.12 325e971b6ba9bfa504672e29be93c24981eeb1c07576d730e9f7c8805afff0c6 https://github.com/rhysd/actionlint/releases/download/v1.7.12/actionlint_1.7.12_linux_arm64.tar.gz actionlint ac0323433c2853ec3fb978c611430c5b3dc5d43c58d1a1ec031b00ab572beb60
zizmor x86_64-linux 1.31.1 d185f726bdaf92df78273217dfdd24ebcd6b0ef48cf3ce776ff5762b6e138c99 https://github.com/zizmorcore/zizmor/releases/download/v1.31.1/zizmor-x86_64-unknown-linux-gnu.tar.gz zizmor dc3bb05237ddd11c62ac19cf5ac1c633acd228e386b7e18f9adb3498873d271f
zizmor aarch64-linux 1.31.1 37eebbd5762a44f262d94875431b14a6d2402991e90a685113ea97b8b41be833 https://github.com/zizmorcore/zizmor/releases/download/v1.31.1/zizmor-aarch64-unknown-linux-gnu.tar.gz zizmor e2cf0a73958aed6646f7937dcf647dd86b52d49eb2b4190a81b17fa63123f8b0
shellcheck x86_64-linux 0.11.0 b7af85e41cc99489dcc21d66c6d5f3685138f06d34651e6d34b42ec6d54fe6f6 https://github.com/koalaman/shellcheck/releases/download/v0.11.0/shellcheck-v0.11.0.linux.x86_64.tar.gz shellcheck-v0.11.0/shellcheck 4da528ddb3a4d1b7b24a59d4e16eb2f5fd960f4bd9a3708a15baddbdf1d5a55b
shellcheck aarch64-linux 0.11.0 68a8133197a50beb8803f8d42f9908d1af1c5540d4bb05fdfca8c1fa47decefc https://github.com/koalaman/shellcheck/releases/download/v0.11.0/shellcheck-v0.11.0.linux.aarch64.tar.gz shellcheck-v0.11.0/shellcheck 127f13925eadd52c341bca0ebaf9ab0dbd78c6468f30a8f262a528bf8de47546
"

# ---- helpers ---------------------------------------------------------------

platform() {
    local os arch
    os="$(uname -s)"
    arch="$(uname -m)"
    case "$arch" in
        x86_64 | amd64) arch=x86_64 ;;
        aarch64 | arm64) arch=aarch64 ;;
    esac
    case "$os" in
        Linux) echo "$arch-linux" ;;
        *) echo "$arch-$os" ;;
    esac
}

sha256_of() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d' ' -f1
    else
        shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

install_one() {
    local tool="$1" plat line version sha url member binary dest tmp archive got
    plat="$(platform)"
    line="$(printf '%s\n' "$PINS" | awk -v t="$tool" -v p="$plat" '$1 == t && $2 == p')"
    if [ -z "$line" ]; then
        if printf '%s\n' "$PINS" | awk -v t="$tool" '$1 == t { found = 1 } END { exit !found }'; then
            die "no pinned $tool build for $plat; install it with your package manager" 2
        fi
        die "unknown tool '$tool' (scripts/ci/install-tool.sh --list)" 2
    fi
    read -r _ _ version sha url member binary <<<"$line"
    [[ "$binary" =~ ^[0-9a-f]{64}$ ]] || die "$tool: no binary SHA-256 pinned" 2
    dest="$TOOLS_DIR/$tool"

    if [ -x "$dest" ] && [ ! -L "$dest" ] && [ "$(sha256_of "$dest")" = "$binary" ]; then
        echo "install-tool: $tool $version already in $TOOLS_DIR (sha256 verified)" >&2
        return 0
    fi

    tmp="$SCRATCH/$tool"
    mkdir "$tmp"
    archive="$tmp/archive.tar.gz"
    echo "install-tool: downloading $tool $version" >&2
    # https only (redirects too), bounded in time and size; the pin decides.
    curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
        --retry 3 --retry-delay 2 --connect-timeout 30 --max-time 600 \
        --max-filesize $((64 * 1024 * 1024)) --output "$archive" "$url" \
        || die "download failed: $url"
    got="$(sha256_of "$archive")"
    if [ "$got" != "$sha" ]; then
        die "$tool $version: SHA-256 mismatch (expected $sha, got $got); refusing to install"
    fi
    mkdir "$tmp/unpacked"
    tar -xzf "$archive" -C "$tmp/unpacked" "$member" || die "$tool: '$member' not found in the archive"
    got="$(sha256_of "$tmp/unpacked/$member")"
    if [ "$got" != "$binary" ]; then
        die "$tool $version: the unpacked binary's SHA-256 is $got, not the pinned $binary; refusing to install"
    fi
    mkdir -p "$TOOLS_DIR"
    rm -f "$dest"
    install -m 0755 "$tmp/unpacked/$member" "$dest"
    echo "install-tool: $tool $version -> $dest (sha256 verified)" >&2
}

# ---- main ------------------------------------------------------------------

[ "$#" -gt 0 ] || die "usage: scripts/ci/install-tool.sh <tool>... | --list" 2

if [ "$1" = "--list" ]; then
    printf '%s\n' "$PINS" | awk 'NF { print $1, $3, $2 }'
    exit 0
fi

if [ -n "${SEAWORTHY_TOOLS_DIR:-}" ]; then
    TOOLS_DIR="$SEAWORTHY_TOOLS_DIR"
elif [ -n "${RUNNER_TEMP:-}" ]; then
    TOOLS_DIR="$RUNNER_TEMP/seaworthy-tools"
else
    TOOLS_DIR="$(git rev-parse --show-toplevel)/target/tools"
fi

SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

for tool in "$@"; do
    install_one "$tool"
done

if [ -n "${GITHUB_PATH:-}" ]; then
    echo "$TOOLS_DIR" >>"$GITHUB_PATH"
fi
