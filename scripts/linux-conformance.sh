#!/usr/bin/env bash
# scripts/linux-conformance.sh — the Linux conformance lane: real packages,
# built by the seaworthy CLI from a real product, installed by each
# distribution's own package manager in containers that run systemd as
# PID 1, and updated by the product's real update helper.
#
#   scripts/linux-conformance.sh build   # the product, its packages and repositories
#   scripts/linux-conformance.sh [all]   # build, then run the suite
#
# CI only (the lab workflow's Linux conformance job): `all` boots systemd
# hosts with CAP_SYS_ADMIN (never privileged; see
# crates/seaworthy-test-support/src/systemd.rs) on the job's own docker
# daemon. Don't point it at a shared daemon.
#
# build: the launcher fixture (crates/seaworthy-launcher/e2e: a launcher
# for plain x86-64, one core per CPU target, seaworthy-updater's real
# update helper `demo_helper` with the lane's seaworthy.toml and keys
# compiled in) built as the CI template builds a product (`seaworthy
# build-plan`'s steps, carried out by scripts/ci/seaworthy.sh build in the
# pinned builder: scripts/lib/lab.sh), with the lane's server (the lab
# server, `conformance_server`: the release tree, the repositories and the
# required-version endpoint the helper's version source asks, run on
# loopback in each host), then three releases of one product, each
# packaged as deb, rpm and pacman by `seaworthy package` and signed with
# throwaway keys (OpenPGP on rpm and pacman, ML-DSA-87 manifests, build
# metadata `conformance`):
#
#   v1  1.0.0, sequence 1   the service and its update helper
#   v2  1.1.0, sequence 2   the same (an upgrade)
#   v3  1.2.0, sequence 3   without the helper (updates off): the helper's
#                           trigger must stop on upgrade
#
# into target/linux-conformance/ (packages/<v>/, keys/repo.asc, bin/, and
# lane.json naming every file). The binaries are the same in every
# release: the lane tests the packages' lifecycle and the update flow, not
# the product. Beside the service, a desktop product (`viewer`: its menu
# entry, icons, data files, /usr/bin link and, with the helper, its update
# unit and polkit rule) from the same repositories.
#
# Every `package` run also builds the repository package (acme-repository,
# deb and rpm, pointing at the lane's server), and the releases rotate the
# OpenPGP key: v1 pins one key (keys/repo.asc); v2 pins it and the next one
# (keys/next.asc), still signed by the first, so its repository package
# carries both; v3 is signed by the next key. The hosts trust it only
# through the repository package's upgrade (Arch: the administrator adds
# it). The update helper is built trusting both, as a product's helper
# released before the switch must.
#
# Then the package repositories: each release published by `seaworthy
# repo` into repos/<v>/ (signed APT, DNF and pacman repositories, the
# release tree the helper fetches from and the repository package in
# setup/, each publication dated after the last and checked against its
# plan with --previous, as a release pipeline publishes), and
# repos/foreign/: v1's repositories with every index signature remade by
# an untrusted key, which every host must refuse to read. The hosts fetch
# them over HTTP from the lane's server, as clients fetch a store.
#
# Also foreign-signed copies of v1's rpm and pacman package (another
# throwaway key) in packages/foreign/, which every host must refuse, and of
# v2's in packages/foreign-v2/, each with a release manifest the TRUSTED key
# signs over the foreign-signed file (seaworthy-updater's sign_release
# example): the helper must refuse them on the package's own signature.
#
# all: then `cargo test -p seaworthy --features conformance --test
# conformance` with SEAWORTHY_CONFORMANCE=target/linux-conformance: the
# suite (crates/seaworthy/tests/conformance.rs) boots each distribution
# (Debian 13, Ubuntu 24.04, UBI 9, Fedora 43, Arch; digest-pinned in
# seaworthy-test-support's images.rs) and checks every lifecycle path and
# the update flow; each distribution's findings land in report/<distro>.json.
# SEAWORTHY_TEST_CONTAINERS_REQUIRED=1 turns a missing daemon into a
# failure.
#
# x86-64 Linux hosts only. Needs gpg, rpmsign, docker, python3, the
# repository tools `seaworthy repo` runs (dpkg-scanpackages, createrepo_c,
# repo-add with bsdtar) and the pinned nFPM (fetched by
# scripts/ci/install-nfpm.sh when NFPM isn't set).
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"

cd "$(git rev-parse --show-toplevel)"
mode="${1:-all}"
case "$mode" in
    build | all) ;;
    *) echo "usage: $0 [build|all]" >&2; exit 2 ;;
esac

# shellcheck source=scripts/lib/lab.sh
. scripts/lib/lab.sh

OUT="$PWD/target/linux-conformance"
TARGET="$LAB_LINUX"
VENDOR=Acme ID=agent SERVICE=AcmeAgent SANDBOX=acme-agent STATE=acme/agent
EXECUTABLE=demo ARGUMENTS=serve
CORE_MARKER='^core='
REPOSITORY="$(echo "$VENDOR" | tr '[:upper:]' '[:lower:]')"
PACKAGE="$REPOSITORY-$ID"
CPUS=(x86-64-v4 x86-64-v3 x86-64-v2)
# One timestamp for every package: the builds are reproducible.
export SOURCE_DATE_EPOCH=1760400000
TOOL_TARGET="${CARGO_TARGET_DIR:-$PWD/target}"

fail() { echo "linux-conformance: FAIL: $*" >&2; exit 1; }
say() { echo "linux-conformance: $*"; }

# One cleanup for every exit path (a failure, Ctrl-C, a cancelled job): the
# builder container, the checkout copy and the gpg homes (agents killed).
CLEANUP_GPG_HOMES=()
cleanup() {
    lab_cleanup
    local home
    for home in "${CLEANUP_GPG_HOMES[@]}"; do
        gpgconf --homedir "$home" --kill all >/dev/null 2>&1 || true
        rm -rf "$home"
    done
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

[ "$(uname -s)-$(uname -m)" = "Linux-x86_64" ] || fail "an x86-64 Linux host is required"
command -v gpg >/dev/null || fail "gpg not found"
command -v rpmsign >/dev/null || fail "rpmsign not found (rpm)"
command -v python3 >/dev/null || fail "python3 not found"
for tool in dpkg-scanpackages createrepo_c repo-add bsdtar; do
    command -v "$tool" >/dev/null || fail "$tool not found (seaworthy repo builds the lane's repositories with it)"
done
if [ -z "${NFPM:-}" ]; then
    NFPM="$(scripts/ci/install-nfpm.sh)"
fi
export NFPM

# The binary `cargo build -p seaworthy` just built (a stale one would test
# old scripts).
seaworthy() {
    "$TOOL_TARGET/debug/seaworthy" "$@"
}

# The product's seaworthy.toml for a release: with the helper (v1, v2) or
# without it (v3), pinning the OpenPGP keys $2 (one, or both).
lane_toml() {
    local helper="$1" keys="$2"
    cat <<TOML
[defaults]
vendor = "$VENDOR"
targets = ["x86-64-v4", "x86-64-v3", "x86-64-v2"]
channel = "stable"
release-signatures = ["ml-dsa-87"]
release-keys = [{ algorithm = "ml-dsa-87", public-key = "keys/release.pub" }]
openpgp-keys = [$keys]
maintainer = "Acme Packaging <conformance@example.com>"
license = "MIT OR Apache-2.0"
homepage = "https://example.com/acme/conformance"

[defaults.repository]
url = "http://127.0.0.1:8470/repo"

[product.agent]
display-name = "Acme conformance agent"
description = "The Linux conformance lane's service."
executable = "demo"
core = "demo_core"
outputs = ["deb", "rpm", "pacman"]
linux.depends.deb = ["libc6 (>= 2.34)"]
linux.depends.rpm = ["glibc >= 2.34"]
linux.depends.pacman = ["glibc"]
TOML
    if [ "$helper" = with-helper ]; then
        echo 'helper = "demo_helper"'
        echo 'updates.default = "auto"'
    else
        echo 'updates.default = "off"'
    fi
    cat <<TOML

[product.agent.service]
name = "$SERVICE"
account = "virtual"
arguments = ["$ARGUMENTS"]
restart-delays = ["15s", "60s"]
state-directory = "$STATE"

[product.agent.service.sandbox]
user = "$SANDBOX"

# A desktop product beside the service: its menu entry, icons, data files
# and /usr/bin link, installed from the same repositories and removed again
# (step 1b). The same launcher and cores. With the helper, its unit and the
# polkit rule letting the logged-in session start it; the binary is the
# lane's helper, built for the agent, which the viewer's unit sandbox stops
# before it does anything (the step checks polkit's verdicts, not an
# update).
[product.viewer]
display-name = "Acme conformance viewer"
description = "The Linux conformance lane's desktop product."
executable = "demo"
core = "demo_core"
kind = "desktop"
outputs = ["deb", "rpm", "pacman"]
TOML
    if [ "$helper" = with-helper ]; then
        echo 'helper = "demo_helper"'
        echo 'updates.default = "auto"'
    else
        echo 'updates.default = "off"'
    fi
    cat <<'TOML'
linux.command = "acme-viewer"
linux.depends.deb = ["libc6 (>= 2.34)"]
linux.depends.rpm = ["glibc >= 2.34"]
linux.depends.pacman = ["glibc"]

[product.viewer.desktop]
linux-icons = ["desktop/icons/viewer-48.png", "desktop/icons/viewer.svg"]
categories = ["Utility"]

[[product.viewer.files]]
source = "desktop/data"
destination = "share"
TOML
}

build_lane() {
    say "building seaworthy and sign_release"
    CARGO_TARGET_DIR="$TOOL_TARGET" cargo build --quiet --locked -p seaworthy --bin seaworthy
    CARGO_TARGET_DIR="$TOOL_TARGET" cargo build --quiet --locked -p seaworthy-updater --example sign_release

    # A previous run's reports never survive a rebuilt lane.
    rm -rf "${OUT:?}/artifacts" "${OUT:?}/packages" "${OUT:?}/keys" "${OUT:?}/work" "${OUT:?}/report" \
        "${OUT:?}/bin" "${OUT:?}/repos" "${OUT:?}/desktop"
    local art="$OUT/artifacts"
    mkdir -p "$art" "$OUT/packages" "$OUT/keys" "$OUT/work" "$OUT/bin"
    # The desktop product's icons and data files (the e2e fixture's),
    # beside the seaworthy.toml files that name them.
    mkdir -p "$OUT/desktop"
    cp -R "$LAB_E2E/desktop/icons" "$LAB_E2E/desktop/data" "$OUT/desktop/"

    # Throwaway keys: the OpenPGP keys in a short-path gpg home (its agent
    # socket), the release key from seaworthy keygen.
    local home
    home="$(mktemp -d /tmp/lab-gpg.XXXXXX)"
    CLEANUP_GPG_HOMES+=("$home")
    chmod 700 "$home"
    gpg --homedir "$home" --batch --quiet --pinentry-mode loopback --passphrase '' \
        --quick-gen-key "Acme conformance <conformance@example.com>" rsa3072 sign never
    local fpr
    fpr="$(gpg --homedir "$home" --list-keys --with-colons | awk -F: '/^fpr:/ { print $10; exit }')"
    gpg --homedir "$home" --armor --export "$fpr" > "$OUT/keys/repo.asc"
    # The rotation's next key: pinned from v2, signing v3.
    gpg --homedir "$home" --batch --quiet --pinentry-mode loopback --passphrase '' \
        --quick-gen-key "Acme conformance next <conformance-next@example.com>" rsa3072 sign never
    local next_fpr
    next_fpr="$(gpg --homedir "$home" --list-keys --with-colons |
        awk -F: '/^fpr:/ { if ($10 != fpr) { print $10; exit } }' fpr="$fpr")"
    [ -n "$next_fpr" ] || fail "the next key wasn't generated"
    gpg --homedir "$home" --armor --export "$next_fpr" > "$OUT/keys/next.asc"
    seaworthy keygen --algorithm ml-dsa-87 --secret "$OUT/keys/release.key" --public "$OUT/keys/release.pub" >/dev/null
    local signer key
    for signer in current next; do
        key="$fpr"
        [ "$signer" = next ] && key="$next_fpr"
        cat > "$OUT/signing-$signer.toml" <<TOML
[[manifest]]
algorithm = "ml-dsa-87"
key = "keys/release.key"

[openpgp]
home = "$home"
key = "$key"
TOML
    done

    # name, version, sequence, helper, pinned keys, signer.
    local specs=(
        "v1 1.0.0 1 with-helper one current"
        "v2 1.1.0 2 with-helper both current"
        "v3 1.2.0 3 without-helper both next"
    )
    local keys name helper
    for spec in "${specs[@]}"; do
        read -r name _ _ helper keys _ <<<"$spec"
        case "$keys" in
            one) keys='"keys/repo.asc"' ;;
            both) keys='"keys/repo.asc", "keys/next.asc"' ;;
        esac
        lane_toml "$helper" "$keys" > "$OUT/seaworthy-$name.toml"
        seaworthy check --config "$OUT/seaworthy-$name.toml" >/dev/null || fail "seaworthy-$name.toml doesn't check"
    done
    seaworthy build-plan --config "$OUT/seaworthy-v1.toml" --triple "$TARGET" \
        --manifest "$LAB_E2E/Cargo.toml" > "$OUT/plan-$TARGET.tsv"
    cat "$OUT/keys/repo.asc" "$OUT/keys/next.asc" > "$OUT/keys/pinned.asc"
    say "building the product (launcher, ${#CPUS[@]} cores, helper: $(grep -c '^build' "$OUT/plan-$TARGET.tsv") cargo builds) and the lane's server in $(lab_builder_image)"
    lab_build_linux "$OUT/plan-$TARGET.tsv" "$art" "$OUT/bin/conformance_server" 1.0.0 conformance \
        "SEAWORTHY_LAB_CONFIG=$OUT/seaworthy-v1.toml" \
        "SEAWORTHY_LAB_RELEASE_PUB=$OUT/keys/release.pub" \
        "SEAWORTHY_LAB_OPENPGP=$OUT/keys/pinned.asc"

    local entries=() version sequence
    for spec in "${specs[@]}"; do
        read -r name version sequence helper keys signer <<<"$spec"
        say "packaging $name ($version, sequence $sequence, $helper, $keys key(s) pinned, signed by the $signer key)"
        seaworthy package --config "$OUT/seaworthy-$name.toml" --artifacts "$art" --out "$OUT/work/$name" \
            --release "$version" --sequence "$sequence" --build conformance --signing "$OUT/signing-$signer.toml" >/dev/null
        mkdir -p "$OUT/packages/$name"
        cp "$OUT/work/$name/$ID/packages/"* "$OUT/packages/$name/"
        entries+=("\"$name\": {\"version\": \"$version\", \"sequence\": $sequence, \"helper\": $([ "$helper" = with-helper ] && echo true || echo false)}")
    done
    # Foreign-signed copies of v1's rpm and pacman package (a second
    # throwaway key, which no host trusts): every package manager must
    # refuse them.
    local foreign
    foreign="$(mktemp -d /tmp/lab-gpgf.XXXXXX)"
    CLEANUP_GPG_HOMES+=("$foreign")
    chmod 700 "$foreign"
    gpg --homedir "$foreign" --batch --quiet --pinentry-mode loopback --passphrase '' \
        --quick-gen-key "not trusted <foreign@example.com>" rsa3072 sign never
    local ffpr
    ffpr="$(gpg --homedir "$foreign" --list-keys --with-colons | awk -F: '/^fpr:/ { print $10; exit }')"
    local release pacman_pkg dir
    for release in v1 v2; do
        dir=foreign
        [ "$release" = v1 ] || dir="foreign-v2"
        mkdir -p "$OUT/packages/$dir"
        cp "$OUT/packages/$release/"*.rpm "$OUT/packages/$dir/"
        rpmsign --resign --define "_openpgp_sign gpg" --define "_gpg_name $ffpr" \
            --define "_gpg_path $foreign" --define "__gpg $(command -v gpg)" "$OUT/packages/$dir/"*.rpm >/dev/null
        pacman_pkg="$(basename "$OUT/packages/$release/"*.pkg.tar.zst)"
        cp "$OUT/packages/$release/$pacman_pkg" "$OUT/packages/$dir/"
        gpg --homedir "$foreign" --batch --yes --no-armor --detach-sign --local-user "$ffpr" \
            --output "$OUT/packages/$dir/$pacman_pkg.sig" "$OUT/packages/$dir/$pacman_pkg"
    done
    # v2's, each with a release manifest the TRUSTED key signs over the
    # foreign-signed file: a manifest the helper accepts, a package
    # signature it must refuse.
    local sign_release="$TOOL_TARGET/debug/examples/sign_release" file format
    pacman_pkg="$(basename "$OUT/packages/v2/"*.pkg.tar.zst)"
    for file in "$OUT/packages/foreign-v2/"*.rpm "$OUT/packages/foreign-v2/$pacman_pkg"; do
        format=rpm
        case "$file" in *.pkg.tar.zst) format=pacman ;; esac
        SEAWORTHY_RELEASE_KEY_HEX="$(tr -d '\n' < "$OUT/keys/release.key")" "$sign_release" mldsa87 "$file" \
            --product "$PACKAGE" --version 1.1.0+conformance --sequence 2 --target "$TARGET" \
            --format "$format" --channel stable >/dev/null
    done

    # The repositories: each release as seaworthy repo publishes it, each
    # publication a day after the last and checked against the last one's
    # plan (apt ignores a Release older than the one it has; no published
    # path may change), and v1's with every index signature remade by the
    # untrusted key.
    mkdir -p "$OUT/repos"
    local epoch="$SOURCE_DATE_EPOCH" previous=()
    for spec in "${specs[@]}"; do
        read -r name _ _ _ _ signer <<<"$spec"
        say "publishing $name's repositories (signed by the $signer key)"
        seaworthy repo --config "$OUT/seaworthy-$name.toml" --packages "$OUT/work/$name" --out "$OUT/repos/$name" \
            --signing "$OUT/signing-$signer.toml" --date "$epoch" "${previous[@]}" >/dev/null
        previous=(--previous "$OUT/repos/$name/publish-plan.json")
        epoch=$((epoch + 86400))
    done
    cmp -s "$OUT/keys/repo.asc" "$OUT/repos/v1/keys/$REPOSITORY.asc" ||
        fail "v1's published key isn't the lane's first key"
    for name in v2 v3; do
        cat "$OUT/keys/repo.asc" "$OUT/keys/next.asc" | cmp -s - "$OUT/repos/$name/keys/$REPOSITORY.asc" ||
            fail "$name's published keys aren't the lane's two keys"
    done
    for name in v1 v2 v3; do
        for file in "$REPOSITORY-repository.deb" "$REPOSITORY-repository.deb.asc" "$REPOSITORY-repository.rpm"; do
            [ -f "$OUT/repos/$name/setup/$file" ] || fail "repos/$name has no setup/$file"
        done
    done
    cp -r "$OUT/repos/v1" "$OUT/repos/foreign"
    local foreign_sign=(gpg --homedir "$foreign" --batch --yes --digest-algo SHA512 --local-user "$ffpr")
    local dists="$OUT/repos/foreign/apt/dists/stable"
    local repodata="$OUT/repos/foreign/rpm/stable/x86_64/repodata"
    local pacman_repo="$OUT/repos/foreign/pacman/stable/x86_64"
    "${foreign_sign[@]}" --armor --detach-sign --output "$dists/Release.gpg" "$dists/Release"
    "${foreign_sign[@]}" --clear-sign --output "$dists/InRelease" "$dists/Release"
    "${foreign_sign[@]}" --armor --detach-sign --output "$repodata/repomd.xml.asc" "$repodata/repomd.xml"
    local db
    for db in "$REPOSITORY.db" "$REPOSITORY.files"; do
        "${foreign_sign[@]}" --no-armor --detach-sign --output "$pacman_repo/$db.tar.zst.sig" "$pacman_repo/$db.tar.zst"
        cp "$pacman_repo/$db.tar.zst.sig" "$pacman_repo/$db.sig"
    done

    local joined
    joined="$(IFS=,; echo "${entries[*]}")"
    local executable="/opt/$REPOSITORY/$ID/$EXECUTABLE" product desktop viewer="$REPOSITORY-viewer"
    product="{\"user\": \"$SANDBOX\", \"state\": \"/var/lib/$STATE\", \"cache\": \"/var/cache/$REPOSITORY/$ID\", \"executable\": \"$executable\", \"arguments\": \"$ARGUMENTS\", \"core-marker\": $(lab_json_string "$CORE_MARKER"), \"token-prefix\": \"\"}"
    # The desktop product (step 1b): where its packages put things, and its
    # helper (v1's packages): the unit the session may start, and the
    # polkit rule saying so.
    desktop="{\"package\": \"$viewer\", \"command\": \"/usr/bin/acme-viewer\", \"launcher\": \"/opt/$REPOSITORY/viewer/demo\", \"entry\": \"/usr/share/applications/$viewer.desktop\", \"icons\": [\"/usr/share/icons/hicolor/48x48/apps/$viewer.png\", \"/usr/share/icons/hicolor/scalable/apps/$viewer.svg\"], \"data\": [\"/opt/$REPOSITORY/viewer/share/readme.txt\", \"/opt/$REPOSITORY/viewer/share/fonts/demo.txt\"], \"root\": \"/opt/$REPOSITORY/viewer\", \"vendor\": \"/opt/$REPOSITORY\", \"helper-unit\": \"$viewer-update.service\", \"polkit-rule\": \"/usr/share/polkit-1/rules.d/60-$viewer-update.rules\"}"
    cat > "$OUT/lane.json" <<JSON
{"package": "$PACKAGE", "service": "$SERVICE", "openpgp-fingerprint": "$fpr", "next-fingerprint": "$next_fpr", "build": "conformance", "server": "bin/conformance_server", "repository": "$REPOSITORY", "repositories": ["v1", "v2", "v3", "foreign"], "releases": {$joined}, "product": $product, "desktop": $desktop}
JSON
    python3 -I -c 'import json, sys; json.load(open(sys.argv[1]))' "$OUT/lane.json" || fail "lane.json isn't JSON"
    say "built: $(find "$OUT/packages" -type f | wc -l) files under $OUT/packages, $(find "$OUT/repos" -type f | wc -l) under $OUT/repos"
}

build_lane
if [ "$mode" = all ]; then
    say "running the suite"
    # The fixture's scenario is required (a skip would pass silently).
    SEAWORTHY_CONFORMANCE="$OUT" SEAWORTHY_CONFORMANCE_PRODUCT=fixture \
        CARGO_TARGET_DIR="$TOOL_TARGET" cargo test --locked -p seaworthy --features conformance \
        --test conformance --no-fail-fast -- --test-threads "${SEAWORTHY_CONFORMANCE_THREADS:-3}"
    for distro in debian-13 ubuntu-24.04 ubi-9 fedora-43 arch; do
        [ -f "$OUT/report/$distro.json" ] || fail "no $OUT/report/$distro.json: the scenario didn't run on $distro"
    done
    say "PASSED on debian-13, ubuntu-24.04, ubi-9, fedora-43 and arch"
fi
