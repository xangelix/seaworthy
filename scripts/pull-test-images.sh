#!/usr/bin/env bash
# Pre-pull the container test images (seaworthy-test-support).
#
# Pulls the digest pins of crates/seaworthy-test-support/src/images.rs
# (`images::ALL`, the ONE list; this script keeps none of its own) ONE AT A
# TIME, before the container suites run, retrying transient registry
# failures (HTTP 429 / toomanyrequests, 5xx, connection resets, timeouts,
# truncated downloads) with the launcher's own bounded, jittered backoff.
# An image the daemon already holds is skipped without a registry request.
# Auth, missing-manifest and digest failures are never retried, and every
# image (a caller's extras included) must be a `name:tag@sha256:…` pin.
#
# Why: a burst of parallel test starts on a cold daemon trips the
# registries' anonymous rate limits; a runner's retry then passes and a
# fail-if-flaky rule (rightly) turns the run red. Warming the daemon
# serially here, and retrying inside the launcher for anything not warmed,
# keeps a registry hiccup out of the test results without loosening
# fail-if-flaky.
#
#   scripts/pull-test-images.sh                          # the suites' services
#   scripts/pull-test-images.sh --only rustfs,debian-13  # by name (--help lists them)
#   scripts/pull-test-images.sh --images-file test-images.txt
#
# The skip contract is the suites': no docker daemon → skipped (exit 0); a
# broken one → exit 1; SEAWORTHY_TEST_CONTAINERS_REQUIRED=1 fails without a
# usable daemon, =0 skips. `--list` prints the selection without contacting
# the daemon.
#
# Implementation: the crate's `pull_test_images` example, the launcher's own
# Rust pull path rather than a shell re-implementation. It is BUILT in this
# checkout (rust-toolchain.toml applies to the working directory, so a
# caller running this by path still gets seaworthy's pinned toolchain;
# `--locked`: the committed lockfile, never a re-resolved graph) and RUN
# from the caller's directory (relative `--images-file` paths mean what the
# caller meant).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# The built example's path, from cargo's artifact message (honours any
# CARGO_TARGET_DIR / build.target-dir); diagnostics still render to stderr.
bin="$(
    cd "$root" &&
        cargo build --quiet --locked -p seaworthy-test-support --example pull_test_images \
            --message-format=json-render-diagnostics |
        sed -n 's/.*"executable":"\([^"]*\)".*/\1/p' | tail -n 1
)"
if [[ -z "$bin" || ! -x "$bin" ]]; then
    echo "pull-test-images: could not build the pull_test_images example (see the cargo output above)" >&2
    exit 1
fi
exec "$bin" "$@"
