# shellcheck shell=bash
# scripts/lib/lab.sh — what the Linux lab lanes share (sourced by
# scripts/linux-conformance.sh and scripts/upgrade-candidate.sh; bash 4.4+,
# `set -euo pipefail` in the caller, run from the repository root).
#
#   lab_builder_image             the pinned Rust builder (test-support's
#                                 images.rs RUST_BUILDER, the one source of
#                                 image pins)
#   lab_build_linux ...           the e2e fixture built for x86-64 Linux in
#                                 that builder, offline (see below)
#   lab_cleanup                   removes what the functions left (call it
#                                 from the caller's EXIT trap)
#
# The fixture's binaries link aws-lc, whose C code needs glibc 2.38 symbols
# when built against a newer glibc; RHEL 9 (UBI 9, the lanes' oldest host)
# has 2.34, and `seaworthy verify` refuses a binary past the product's
# floor. So they are built in the pinned builder (Debian 12, glibc 2.36,
# whose builds need no symbol past 2.34), through docker: a copy of the
# checkout and its vendored crates go in (`cargo vendor` from the e2e
# workspace's lockfile, on this side: cargo checks each crate's checksum),
# the build runs with no network at all and the image's own toolchain
# (which must be rust-toolchain.toml's), the artifacts come out, and the
# container and the copy are removed on every exit path. The container is
# unprivileged.

LAB_E2E=crates/seaworthy-launcher/e2e
LAB_LINUX=x86_64-unknown-linux-gnu
LAB_CLEANUP_CONTAINER=""
LAB_CLEANUP_DIRS=()

lab_cleanup() {
    if [ -n "$LAB_CLEANUP_CONTAINER" ]; then
        docker rm -f "$LAB_CLEANUP_CONTAINER" >/dev/null 2>&1 || true
        LAB_CLEANUP_CONTAINER=""
    fi
    if [ "${#LAB_CLEANUP_DIRS[@]}" -gt 0 ]; then
        rm -rf "${LAB_CLEANUP_DIRS[@]}"
        LAB_CLEANUP_DIRS=()
    fi
}

lab_fail() { echo "lab: FAIL: $*" >&2; exit 1; }

lab_builder_image() {
    awk '/pub const RUST_BUILDER: &str/ { found = 1 }
         found && match($0, /"[^"]+"/) { print substr($0, RSTART + 1, RLENGTH - 2); exit }' \
        crates/seaworthy-test-support/src/images.rs
}

# lab_build_linux <plan.tsv> <out artifacts dir> <out server binary> \
#                 <version> <build> [VAR=VALUE...]
#
# Builds what the plan names (`seaworthy build-plan --triple
# x86_64-unknown-linux-gnu --manifest crates/seaworthy-launcher/e2e/Cargo.toml`)
# through the CI template's build step (scripts/ci/seaworthy.sh build), as a
# product's pipeline does, then the lab server (`conformance_server`), in
# the pinned builder. The release is <version>+<build>. Each VAR=VALUE is
# the demo helper's build input (SEAWORTHY_LAB_*, demo_helper/build.rs): a
# value naming a file on this side is copied in and passed as its path
# inside; any other value is passed as is. SEAWORTHY_ALLOW_CI_TEST_KEYS=1
# (that value alone) builds the plan with seaworthy-formats' CI test-key
# switch, for a helper given SEAWORTHY_LAB_CI_TEST_PUB: a lab build, never
# a release (seaworthy.sh refuses the switch on one); the lab server is
# built without it.
lab_build_linux() {
    local plan="$1" artifacts="$2" server="$3" version="$4" build="$5"
    shift 5
    command -v docker >/dev/null || lab_fail "docker not found (the lab builds in the pinned builder image)"
    local image channel src
    image="$(lab_builder_image)"
    [ -n "$image" ] || lab_fail "no RUST_BUILDER pin in crates/seaworthy-test-support/src/images.rs"
    channel="$(sed -n 's/^channel = "\(.*\)"$/\1/p' rust-toolchain.toml)"
    case "$image" in
        "rust:$channel-"*) ;;
        *) lab_fail "the builder $image doesn't carry the pinned toolchain $channel: bump images::RUST_BUILDER with rust-toolchain.toml" ;;
    esac
    src="$(mktemp -d "${TMPDIR:-/tmp}/lab-src.XXXXXX")"
    LAB_CLEANUP_DIRS+=("$src")
    mkdir -p "$src/src/lab-inputs"
    git ls-files -co --exclude-standard -z | tar --null -T - -cf - | tar -xf - -C "$src/src"
    cargo vendor --quiet --locked --versioned-dirs --manifest-path "$LAB_E2E/Cargo.toml" \
        "$src/src/vendor" >/dev/null
    # A fresh work directory: one left in the checkout would name another
    # release than the one built here.
    rm -rf "$src/src/lab-work"
    mkdir -p "$src/src/lab-work"
    cp "$plan" "$src/src/lab-work/plan-$LAB_LINUX.tsv"
    local env=() assignment name value index=0
    for assignment in "$@"; do
        name="${assignment%%=*}"
        value="${assignment#*=}"
        case "$name=$value" in
            SEAWORTHY_LAB_[A-Z_]*=*) ;;
            SEAWORTHY_ALLOW_CI_TEST_KEYS=1) env+=(-e "$name=$value"); continue ;;
            *) lab_fail "not a demo helper input: $name" ;;
        esac
        if [ -f "$value" ]; then
            index=$((index + 1))
            cp "$value" "$src/src/lab-inputs/$index-$(basename "$value")"
            value="/src/lab-inputs/$index-$(basename "$value")"
        fi
        env+=(-e "$name=$value")
    done
    local offline="--offline --config source.crates-io.replace-with=\"vendored\" --config source.vendored.directory=\"/src/vendor\""
    # CARGO_BUILD_JOBS passes through when set (a shared machine's limit).
    LAB_CLEANUP_CONTAINER="$(docker create --network none -w /src -e CARGO_INCREMENTAL=0 \
        -e CARGO_BUILD_JOBS \
        -e RUSTUP_TOOLCHAIN="$channel" -e RUSTUP_AUTO_INSTALL=0 \
        -e SEAWORTHY_WORK=lab-work \
        -e SEAWORTHY_MANIFEST="$LAB_E2E/Cargo.toml" \
        -e SEAWORTHY_CARGO_ARGS="$offline" \
        -e SEAWORTHY_VERSION="$version" \
        -e SEAWORTHY_BUILD_COMMAND="printf %s $build" \
        "${env[@]}" \
        "$image" bash -c "set -euo pipefail
            bash scripts/ci/seaworthy.sh build $LAB_LINUX
            # Word-split, never re-parsed: the TOML quotes stay. The lab
            # server trusts no key: never with the CI test-key switch.
            env -u SEAWORTHY_ALLOW_CI_TEST_KEYS \
                cargo build --quiet --locked --release --target $LAB_LINUX \$SEAWORTHY_CARGO_ARGS \
                --manifest-path $LAB_E2E/Cargo.toml -p conformance_server")"
    tar -C "$src" -cf - src | docker cp - "$LAB_CLEANUP_CONTAINER:/" ||
        lab_fail "copying the checkout into the builder failed"
    docker start -a "$LAB_CLEANUP_CONTAINER" || lab_fail "building the fixture and the lab server in $image failed"
    mkdir -p "$artifacts" "$(dirname "$server")"
    if ! docker cp "$LAB_CLEANUP_CONTAINER:/src/lab-work/artifacts/$LAB_LINUX" "$artifacts/" ||
        ! docker cp "$LAB_CLEANUP_CONTAINER:/src/$LAB_E2E/target/$LAB_LINUX/release/conformance_server" "$server"; then
        lab_fail "copying the binaries out of the builder failed"
    fi
    lab_cleanup
}

# lab_json_string <text>: <text> as a JSON string.
lab_json_string() {
    python3 -I -c 'import json, sys; print(json.dumps(sys.argv[1]))' "$1"
}
