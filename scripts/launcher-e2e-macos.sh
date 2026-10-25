#!/usr/bin/env bash
# scripts/launcher-e2e-macos.sh — seaworthy-launcher end to end on Apple
# Silicon macOS: the fixture product (crates/seaworthy-launcher/e2e) laid out
# as a macOS product — the launcher in an app bundle's Contents/MacOS, one
# core per CPU target in Contents/Frameworks, each built in its own target
# directory with `-C target-cpu=<cpu>` and nothing else — and checked on
# real binaries:
#
#   - the Mach-O records survive the shipped profile (thin LTO, strip): each
#     core's __DATA,__cpureq and the launcher's __DATA,__cpulist read back;
#   - the launcher skips the apple-m4 core (its record carries v8.5a and
#     later, which macOS reports no signal for) and runs apple-m1;
#   - SEAWORTHY_CORE: apple-m1 runs, apple-m4 is refused (78), a CPU name
#     that isn't one of the product's is refused (64);
#   - started through a symlink outside the bundle, it still finds its cores
#     (the launcher resolves its own path);
#   - argument, exit-code, panic (101) and unflushed-stdout pass-through;
#   - a missing apple-m1 core, or one carrying another build's record, is a
#     damaged install (74), never "CPU too old";
#   - the build refuses a core enabling a feature no aarch64 record can name.
#
#   scripts/launcher-e2e-macos.sh
#
# Requirements: Apple Silicon macOS 11 or newer; bash 4.4 or newer (macOS's
# /bin/bash is 3.2: put Homebrew's bash first on PATH); git; rustup with the
# toolchain rust-toolchain.toml pins and its aarch64-apple-darwin target;
# file(1). Elsewhere it SKIPs, or fails with
# SEAWORTHY_LAUNCHER_E2E_REQUIRED=1 (CI). Builds go to
# ${CARGO_TARGET_DIR:-target}/launcher-e2e-macos.
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"

cd "$(git rev-parse --show-toplevel)"
FIXTURE=crates/seaworthy-launcher/e2e
OUT="${CARGO_TARGET_DIR:-$PWD/target}/launcher-e2e-macos"
TARGET=aarch64-apple-darwin
CPUS=(apple-m4 apple-m1)
REQUIRED="${SEAWORTHY_LAUNCHER_E2E_REQUIRED:-0}"

fail() { echo "launcher-e2e-macos: FAIL: $*" >&2; exit 1; }
ok() { echo "launcher-e2e-macos: ok    $*"; }
skip() {
    if [ "$REQUIRED" = 1 ]; then fail "$* (SEAWORTHY_LAUNCHER_E2E_REQUIRED=1)"; fi
    echo "launcher-e2e-macos: SKIP  $*"
}

[ "$(uname -s)-$(uname -m)" = "Darwin-arm64" ] || { skip "not an Apple Silicon macOS host"; exit 0; }

build() { # <target-dir> <rustflags> <package> [cargo args…]
    local dir="$1" flags="$2" package="$3"
    shift 3
    RUSTFLAGS="$flags" CARGO_TARGET_DIR="$dir" cargo build --quiet --release --locked \
        --manifest-path "$FIXTURE/Cargo.toml" --target "$TARGET" -p "$package" "$@"
}

# run <expected exit> <expected stdout+stderr substring> <command…>
run() {
    local want_rc="$1" want_text="$2"
    shift 2
    local out rc=0
    out="$("$@" 2>&1)" || rc=$?
    [ "$rc" = "$want_rc" ] || fail "$* exited $rc (expected $want_rc): $out"
    case "$out" in *"$want_text"*) ;; *) fail "$*: expected \"$want_text\" in: $out" ;; esac
}

rm -rf "${OUT:?}/Demo.app" "${OUT:?}/damaged" "${OUT:?}/mixed" "${OUT:?}/bin"
build "$OUT/launcher" "" demo
build "$OUT/launcher" "" inspect
for cpu in "${CPUS[@]}"; do
    build "$OUT/core-$cpu" "-C target-cpu=$cpu" demo_core
done
ok "built the launcher (apple-m1 default) and cores ${CPUS[*]}"

APP="$OUT/Demo.app/Contents"
mkdir -p "$APP/MacOS" "$APP/Frameworks"
cp "$OUT/launcher/$TARGET/release/demo" "$APP/MacOS/demo"
for cpu in "${CPUS[@]}"; do
    cp "$OUT/core-$cpu/$TARGET/release/libdemo_core.dylib" "$APP/Frameworks/libdemo_core_$cpu.dylib"
done
DEMO="$APP/MacOS/demo"
INSPECT="$OUT/launcher/$TARGET/release/inspect"

# The records, read back from the shipped (stripped, LTO) Mach-O files.
file "$DEMO" | grep -q "Mach-O 64-bit executable arm64" || fail "$DEMO: $(file "$DEMO")"
run 0 "cpus=apple-m4,apple-m1" "$INSPECT" cpulist "$DEMO"
for cpu in "${CPUS[@]}"; do
    core="$APP/Frameworks/libdemo_core_$cpu.dylib"
    run 0 "target=$TARGET
cpu=$cpu" "$INSPECT" cpureq "$core"
    run 0 "neon" "$INSPECT" cpureq "$core"
done
run 0 "v8.7a" "$INSPECT" cpureq "$APP/Frameworks/libdemo_core_apple-m4.dylib"
ok "the Mach-O records survive thin LTO and strip (__DATA,__cpureq, __DATA,__cpulist)"

# Selection: apple-m4 is skipped (no signal for v8.5a and later), apple-m1 runs.
run 0 "core=apple-m1" "$DEMO"
# (What else it lacks depends on the chip: an M1 also lacks bf16, i8mm, …)
run 0 "skipped apple-m4: needs" env SEAWORTHY_LAUNCHER_DEBUG=1 "$DEMO"
run 0 "v8.7a" env SEAWORTHY_LAUNCHER_DEBUG=1 "$DEMO"
run 0 "core=apple-m1" env SEAWORTHY_CORE=apple-m1 "$DEMO"
run 78 "can't run that build" env SEAWORTHY_CORE=apple-m4 "$DEMO"
run 64 "is not one of this program's builds" env SEAWORTHY_CORE=x86-64-v3 "$DEMO"
ok "the launcher skips apple-m4 and runs apple-m1; SEAWORTHY_CORE and its refusals"

# Through a symlink outside the bundle: the cores are found beside the real file.
mkdir -p "$OUT/bin"
ln -s "$DEMO" "$OUT/bin/demo"
run 0 "core=apple-m1" "$OUT/bin/demo"
ok "started through a symlink, it finds the bundle's cores"

# Pass-through.
run 0 "args=args a b c" "$DEMO" args a "b c"
run 7 "core=apple-m1" "$DEMO" exit 7
run 101 "the core panicked on request" "$DEMO" panic
run 0 "no newline at the end" "$DEMO" partial-line
ok "arguments, exit codes, panics and unflushed stdout pass through"

# A damaged install is never "CPU too old".
cp -R "$OUT/Demo.app" "$OUT/damaged"
rm "$OUT/damaged/Contents/Frameworks/libdemo_core_apple-m1.dylib"
run 74 "repair or reinstall" "$OUT/damaged/Contents/MacOS/demo"
cp -R "$OUT/Demo.app" "$OUT/mixed"
cp "$APP/Frameworks/libdemo_core_apple-m4.dylib" "$OUT/mixed/Contents/Frameworks/libdemo_core_apple-m1.dylib"
run 74 "carries the record of another build" "$OUT/mixed/Contents/MacOS/demo"
ok "a missing or mismatched apple-m1 core is a damaged install (74)"

# The build refuses what no aarch64 record could name.
out="$(RUSTFLAGS="-C target-cpu=apple-m1 -C target-feature=+avx2" CARGO_TARGET_DIR="$OUT/refused" \
    cargo build --quiet --release --locked --manifest-path "$FIXTURE/Cargo.toml" --target "$TARGET" \
    -p demo_core 2>&1)" && fail "a core enabling +avx2 built: $out"
case "$out" in *"enables avx2, which seaworthy-levels has no row for"*) ;; *) fail "unexpected refusal: $out" ;; esac
ok "the build refuses a feature no aarch64 record can name"

echo "launcher-e2e-macos: all checks passed"
