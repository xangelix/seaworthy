#!/usr/bin/env bash
# scripts/launcher-e2e.sh — seaworthy-launcher end to end: build the fixture
# product (crates/seaworthy-launcher/e2e) exactly as a packaging tool lays a
# product out — a launcher built for plain x86-64, one core per CPU target,
# each in its own target directory with `-C target-cpu=<cpu>` and nothing
# else — and check, on real binaries, that:
#
#   selection   the records survive the shipped profile (thin LTO, strip);
#               the launcher picks the core the kernel's own CPU flags say
#               it should natively, and the right one under qemu-user's CPU
#               models (qemu64 → exit 78 below the v2 floor, Nehalem → v2,
#               Haswell → v3, a model whose AVX-512 TCG masks → v3); the
#               SEAWORTHY_CORE override and its refusals; the fallback past
#               a missing or mismatched core; a damaged or incomplete
#               install (exit 74, never "CPU too old" when the core it needs
#               is missing); argument, exit-code, panic (101) and unflushed
#               stdout pass-through; each core's libm hypot and hypotf bound
#               to glibc's baseline versions (glibc_floor!, the glibc floor
#               on any host glibc); the build-time refusals (flags only the
#               core crate saw, an enabled feature no record can name); the
#               APX record of a CPU target `--print cfg` under-reports;
#               `seaworthy verify` and `layout` over the real launcher and
#               cores, and the laid-out tree running (so the layout matches
#               the launcher's core lookup); and, when cargo-xwin is
#               present, that the records survive the Windows (PE,
#               lld-link) build too.
#   fips        the AWS-LC FIPS module inside a per-CPU core
#               (seaworthy-crypto's `fips` feature): the power-on
#               self-tests pass in the loaded core, stripped as shipped too;
#               `seaworthy fips-check` agrees with
#               scripts/verify-fips-binary.sh on the real core, both ways;
#               and with one bit flipped inside the module's text the
#               integrity test aborts the process before any product code
#               runs.
#
#   scripts/launcher-e2e.sh [selection|fips|all]      (default: selection)
#
# Requirements: an x86-64 Linux host with glibc; bash 4.4 or newer; git;
# rustup with the toolchain rust-toolchain.toml pins (cargo and rustc on
# PATH, or in ~/.cargo/bin); binutils' readelf; getconf; grep, awk and
# coreutils. Optional:
#   - qemu-user's `qemu-x86_64` (or the binary QEMU_X86_64 names; CI can
#     install a pinned static one with scripts/ci-qemu.sh) for the
#     emulated-CPU checks;
#   - cargo-xwin (with network access to fetch the MSVC CRT and SDK on
#     first use, or a populated XWIN_CACHE_DIR) for the Windows build check.
# Without an optional tool its checks SKIP (loudly), unless
# SEAWORTHY_LAUNCHER_E2E_REQUIRED=1 (CI), which turns a skip into a
# failure. SEAWORTHY_LAUNCHER_E2E_WINDOWS=0 leaves the Windows build check
# out explicitly (said so in the log, never a skip): for a run beside the
# Windows lanes, which check the PE records natively. The fips mode needs
# what the AWS-LC FIPS module builds with (Clang, CMake, Go, Perl), nm and
# python3. Builds go to ${CARGO_TARGET_DIR:-target}/launcher-e2e; the
# seaworthy CLI is built into ${CARGO_TARGET_DIR:-target} itself.
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"

cd "$(git rev-parse --show-toplevel)"
mode="${1:-selection}"
case "$mode" in selection | fips | all) ;; *) echo "usage: $0 [selection|fips|all]" >&2; exit 2 ;; esac

FIXTURE=crates/seaworthy-launcher/e2e
OUT="${CARGO_TARGET_DIR:-$PWD/target}/launcher-e2e"
TARGET=x86_64-unknown-linux-gnu
CPUS=(x86-64-v4 x86-64-v3 x86-64-v2)
REQUIRED="${SEAWORTHY_LAUNCHER_E2E_REQUIRED:-0}"
WINDOWS_CHECK="${SEAWORTHY_LAUNCHER_E2E_WINDOWS:-1}"
# The seaworthy CLI's target directory (the repository's); each fixture
# build below picks its own.
TOOL_TARGET="${CARGO_TARGET_DIR:-$PWD/target}"
unset CARGO_TARGET_DIR

fail() { echo "launcher-e2e: FAIL: $*" >&2; exit 1; }
ok() { echo "launcher-e2e: ok    $*"; }
skip() {
    if [ "$REQUIRED" = 1 ]; then fail "$* (SEAWORTHY_LAUNCHER_E2E_REQUIRED=1)"; fi
    echo "launcher-e2e: SKIP  $*"
}

[ "$(uname -s)-$(uname -m)" = "Linux-x86_64" ] || { skip "not an x86-64 Linux host"; exit 0; }
command -v readelf >/dev/null || fail "readelf not found (install binutils)"

build() { # <target-dir> <package> [extra cargo args…] (RUSTFLAGS from the caller)
    local dir="$1" package="$2"
    shift 2
    CARGO_TARGET_DIR="$dir" cargo build --quiet --locked --manifest-path "$FIXTURE/Cargo.toml" \
        --target "$TARGET" -p "$package" "$@"
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

# build_fails <expected output substring> <target-dir> <cargo subcommand>
# [cargo args…] [-- rustc args…] — a build that must be refused (RUSTFLAGS
# from the caller).
build_fails() {
    local want_text="$1" dir="$2" subcommand="$3"
    shift 3
    local out rc=0
    out="$(CARGO_TARGET_DIR="$dir" cargo "$subcommand" --quiet --locked --manifest-path "$FIXTURE/Cargo.toml" \
        --target "$TARGET" "$@" 2>&1)" || rc=$?
    [ "$rc" != 0 ] || fail "cargo $subcommand $* succeeded; it must be refused"
    case "$out" in *"$want_text"*) ;; *) fail "cargo $subcommand $*: expected \"$want_text\" in: $out" ;; esac
}

# The x86-64 level the kernel reports this CPU at (from /proc/cpuinfo, an
# oracle independent of seaworthy-levels): the core the launcher must choose.
cpu_has() { # <" flag flag … "> <flag…>
    local flags="$1" f
    shift
    for f in "$@"; do case "$flags" in *" $f "*) ;; *) return 1 ;; esac; done
}
native_level() {
    local flags
    flags=" $(grep -m1 '^flags' /proc/cpuinfo | cut -d: -f2) "
    if cpu_has "$flags" avx512f avx512bw avx512cd avx512dq avx512vl avx avx2 bmi1 bmi2 f16c fma abm movbe xsave cx16 lahf_lm popcnt sse4_1 sse4_2 ssse3; then
        echo x86-64-v4
    elif cpu_has "$flags" avx avx2 bmi1 bmi2 f16c fma abm movbe xsave cx16 lahf_lm popcnt sse4_1 sse4_2 ssse3; then
        echo x86-64-v3
    elif cpu_has "$flags" cx16 lahf_lm popcnt sse4_1 sse4_2 ssse3; then
        echo x86-64-v2
    else
        echo none
    fi
}

layout() { # <install dir> <profile dir name> — the launcher and every core
    local dir="$1" profile="$2"
    rm -rf "$dir"
    mkdir -p "$dir/lib"
    cp "$OUT/launcher/$TARGET/$profile/demo" "$dir/demo"
    for cpu in "${CPUS[@]}"; do
        cp "$OUT/core-$cpu/$TARGET/$profile/libdemo_core.so" "$dir/lib/libdemo_core_$cpu.so"
    done
}

# The seaworthy CLI, built from this checkout.
seaworthy() {
    CARGO_TARGET_DIR="$TOOL_TARGET" cargo build --quiet --locked -p seaworthy --bin seaworthy
    "$TOOL_TARGET/debug/seaworthy" "$@"
}

# The seaworthy CLI over the real release binaries: the artifact directory
# a product's build job leaves, a product configuration, verify, layout,
# and the laid-out tree run in place.
dist_check() {
    local level="$1"
    local art="$OUT/dist-artifacts" cfg="$OUT/seaworthy.toml" out="$OUT/dist-out"
    rm -rf "$art" "$out"
    mkdir -p "$art/$TARGET/launcher"
    cp "$OUT/launcher/$TARGET/release/demo" "$art/$TARGET/launcher/demo"
    for cpu in "${CPUS[@]}"; do
        mkdir -p "$art/$TARGET/cores/$cpu"
        cp "$OUT/core-$cpu/$TARGET/release/libdemo_core.so" "$art/$TARGET/cores/$cpu/"
    done
    cat > "$cfg" <<'TOML'
[defaults]
vendor = "Acme"
targets = ["x86-64-v4", "x86-64-v3", "x86-64-v2"]
channel = "stable"
release-signatures = ["ml-dsa-87"]
maintainer = "Acme Packaging <packages@example.com>"
license = "MIT OR Apache-2.0"

[product.demo]
display-name = "Acme launcher demo"
description = "seaworthy-launcher's end-to-end fixture."
executable = "demo"
core = "demo_core"
kind = "tool"
outputs = ["tar"]
updates.default = "off"
TOML
    run 0 "demo $TARGET: verified (3 cores)" seaworthy verify --config "$cfg" --artifacts "$art"
    run 0 "4 files under /opt/acme/demo" seaworthy layout --config "$cfg" --artifacts "$art" --out "$out"
    local laid_out="$out/demo/$TARGET/tree/opt/acme/demo/demo"
    if [ "$level" = none ]; then
        run 78 "this CPU can't run any build" "$laid_out"
    else
        run 0 "core=$level" "$laid_out"
    fi
    # A core carrying another build's record is refused, naming it.
    cp "$art/$TARGET/cores/x86-64-v2/libdemo_core.so" "$art/$TARGET/cores/x86-64-v3/libdemo_core.so"
    run 1 "built for CPU x86-64-v2, but sits in the x86-64-v3 build" seaworthy verify --config "$cfg" --artifacts "$art"
    ok "seaworthy: verify and layout over the real launcher and cores; the laid-out tree runs ($level); a swapped core is refused"
}

selection() {
    echo "launcher-e2e: building the launcher (plain x86-64) and ${#CPUS[@]} cores (release, LTO, stripped)"
    RUSTFLAGS="" build "$OUT/launcher" demo --release
    RUSTFLAGS="" build "$OUT/inspect" inspect --release
    for cpu in "${CPUS[@]}"; do
        RUSTFLAGS="-C target-cpu=$cpu" build "$OUT/core-$cpu" demo_core --release
    done
    local inspect="$OUT/inspect/$TARGET/release/inspect"
    local dir="$OUT/install"
    layout "$dir" release

    # The records survive the shipped profile, and match the file names.
    run 0 "cpus=x86-64-v4,x86-64-v3,x86-64-v2" "$inspect" cpulist "$dir/demo"
    for cpu in "${CPUS[@]}"; do
        run 0 "cpu=$cpu" "$inspect" cpureq "$dir/lib/libdemo_core_$cpu.so"
    done
    run 0 "features=avx,avx2,bmi1,bmi2,cmpxchg16b,f16c,fma,fxsr,lahfsahf,lzcnt,movbe,popcnt,sse,sse2,sse3,sse4.1,sse4.2,ssse3,x87,xsave" \
        "$inspect" cpureq "$dir/lib/libdemo_core_x86-64-v3.so"
    # The launcher is baseline: no core record of its own reaches it.
    run 1 "no \`.cpureq\` section" "$inspect" cpureq "$dir/demo"
    ok "records: the launcher's CPU list and each core's requirement survive LTO and stripping"

    # Natively: the best core runs, and the program behaves as itself.
    local level
    level="$(native_level)"
    if [ "$level" = none ]; then
        run 78 "this CPU can't run any build of this program" "$dir/demo"
    else
        run 0 "core=$level" "$dir/demo"
    fi
    run 42 "core=" "$dir/demo" exit 42
    run 0 "args=args one two" "$dir/demo" args one two
    run 101 "the core panicked on request" "$dir/demo" panic
    # A last line without a newline: the core's own stdout buffer must be
    # flushed before the launcher exits.
    local partial_out
    partial_out="$("$dir/demo" partial-line)"
    [[ "$partial_out" == *$'\n'"no newline at the end" ]] || fail "the core's unflushed stdout was lost: \"$partial_out\""
    ok "native: the core the kernel's CPU flags call for ($level) runs in-process; arguments, exit codes, panics and unflushed output pass through"

    # The glibc floor (glibc_floor!): libm's hypot and hypotf bind to
    # glibc's baseline versions, never GLIBC_2.35, however new this host's
    # glibc is — and still compute through libm.
    if [ "$level" != none ]; then
        run 0 "hypot=5 hypotf=13 overflow=inf" "$dir/demo" hypot
    fi
    local core syms
    for core in "$dir"/lib/libdemo_core_*.so; do
        syms="$(readelf --dyn-syms -W "$core")"
        grep -Eq ' hypot@GLIBC_2\.2\.5( |$)' <<<"$syms" || fail "$core: hypot isn't bound to GLIBC_2.2.5: $(grep hypot <<<"$syms")"
        grep -Eq ' hypotf@GLIBC_2\.2\.5( |$)' <<<"$syms" || fail "$core: hypotf isn't bound to GLIBC_2.2.5: $(grep hypot <<<"$syms")"
        ! grep -Eq 'hypotf?@+GLIBC_2\.(3[5-9]|[4-9][0-9])' <<<"$syms" || fail "$core: hypot needs a glibc past the floor: $(grep hypot <<<"$syms")"
        ! grep -Eq ' hypotf?$' <<<"$syms" || fail "$core: exports its hypot stubs: $(grep hypot <<<"$syms")"
    done
    # The launcher (an executable, which would export an unhidden stub and
    # interpose libm for every library in the process) exports neither.
    syms="$(readelf --dyn-syms -W "$dir/demo")"
    ! grep -Eq ' hypotf?$' <<<"$syms" || fail "the launcher exports its hypot stubs: $(grep hypot <<<"$syms")"
    ok "glibc floor: each core's hypot and hypotf bind to GLIBC_2.2.5 (this host: glibc $(getconf GNU_LIBC_VERSION | cut -d' ' -f2)), compute, and neither a core nor the launcher exports the stubs"

    # The overrides.
    run 0 "core=x86-64-v2" env SEAWORTHY_CORE=x86-64-v2 "$dir/demo"
    run 64 "SEAWORTHY_CORE=znver9 is not one of this program's builds" env SEAWORTHY_CORE=znver9 "$dir/demo"
    run 0 "loading x86-64-v" env SEAWORTHY_LAUNCHER_DEBUG=1 "$dir/demo"
    run 0 "host features:" env SEAWORTHY_LAUNCHER_DEBUG=1 "$dir/demo"
    ok "overrides: SEAWORTHY_CORE forces a supported core, refuses an unknown one; SEAWORTHY_LAUNCHER_DEBUG explains"

    # A missing core falls back (with a note); a mismatched one is damage.
    local partial="$OUT/install-partial"
    layout "$partial" release
    rm "$partial/lib/libdemo_core_x86-64-v4.so"
    cp "$partial/lib/libdemo_core_x86-64-v2.so" "$partial/lib/libdemo_core_x86-64-v3.so"
    run 0 "skipped x86-64-v3: the file carries the record of another build (x86-64-v2)" "$partial/demo"
    run 0 "skipped x86-64-v4: missing" "$partial/demo"
    run 0 "core=x86-64-v2" "$partial/demo"
    rm "$partial/lib/"*.so
    run 74 "no build of this program that this CPU can run was found" "$partial/demo"
    printf 'not a core\n' > "$partial/lib/libdemo_core_x86-64-v2.so"
    run 74 "x86-64-v2: unreadable" "$partial/demo"
    ok "damage: a missing core is skipped with a note; no readable core exits 74"

    # Emulated CPUs (qemu-user).
    local qemu="${QEMU_X86_64:-qemu-x86_64}"
    if command -v "$qemu" >/dev/null 2>&1; then
        echo "launcher-e2e: emulating with $("$qemu" --version | head -n1)"
        local q=("$qemu" -cpu)
        run 78 "the least demanding build (x86-64-v2) needs" "${q[@]}" qemu64 "$dir/demo"
        run 78 "qemu64" "${q[@]}" qemu64 "$dir/demo"
        run 0 "core=x86-64-v2" "${q[@]}" Nehalem "$dir/demo"
        run 0 "core=x86-64-v3" "${q[@]}" Haswell "$dir/demo"
        # TCG doesn't implement the model's AVX-512 and clears those CPUID
        # bits: reading CPUID, the launcher picks v3 — never v4 from the
        # model's name.
        run 0 "core=x86-64-v3" "${q[@]}" Icelake-Server "$dir/demo"
        run 78 "SEAWORTHY_CORE=x86-64-v4: this CPU can't run that build" env SEAWORTHY_CORE=x86-64-v4 "${q[@]}" Haswell "$dir/demo"
        # The core a v2 CPU needs is missing: damage (74), not "too old".
        local incomplete="$OUT/install-incomplete"
        layout "$incomplete" release
        rm "$incomplete/lib/libdemo_core_x86-64-v2.so"
        run 74 "x86-64-v2: missing" "${q[@]}" Nehalem "$incomplete/demo"
        run 74 "x86-64-v3: needs " "${q[@]}" Nehalem "$incomplete/demo"
        ok "emulated CPUs: qemu64 below the floor (78), Nehalem v2, Haswell v3, masked AVX-512 v3, override refused, missing v2 core is damage (74)"
    else
        skip "emulated CPUs: $qemu not found (install qemu-user, or run scripts/ci-qemu.sh and set QEMU_X86_64)"
    fi

    # Build-time refusals (debug profile: they fail before linking).
    # Flags only the core crate sees: the record (written for the default
    # CPU) would describe another build.
    RUSTFLAGS="" build_fails "disagree on" "$OUT/refuse-flags" rustc -p demo_core -- -C target-cpu=x86-64-v3
    # A feature no record can name (APX's NF, which rustc passes to LLVM).
    RUSTFLAGS="-C target-feature=+nf" build_fails "which seaworthy-levels has no row for" "$OUT/refuse-unknown" \
        build -p demo_core
    ok "build refusals: core-crate-only CPU flags and an unnamed feature fail the build"

    # A CPU target that uses APX without `--print cfg` reporting `apxf`.
    RUSTFLAGS="-C target-cpu=diamondrapids" build "$OUT/core-diamondrapids" demo_core
    local apx_features
    apx_features="$("$inspect" cpureq "$OUT/core-diamondrapids/$TARGET/debug/libdemo_core.so" | grep '^features=')"
    case ",${apx_features#features=}," in *,apxf,*) ;; *) fail "the diamondrapids record lacks apxf: $apx_features" ;; esac
    ok "implied features: a diamondrapids core's record lists apxf"

    dist_check "$level"

    # The Windows build keeps the records too (PE, lld-link).
    if [ "$WINDOWS_CHECK" = 0 ]; then
        echo "launcher-e2e: not run: the Windows build check (SEAWORTHY_LAUNCHER_E2E_WINDOWS=0; the Windows lanes check PE records natively)"
    elif command -v cargo-xwin >/dev/null 2>&1; then
        local wt=x86_64-pc-windows-msvc
        rustup target add "$wt" >/dev/null
        CARGO_TARGET_DIR="$OUT/win-launcher" cargo xwin build --quiet --locked --manifest-path "$FIXTURE/Cargo.toml" \
            --target "$wt" -p demo --release
        RUSTFLAGS="-C target-cpu=x86-64-v3" CARGO_TARGET_DIR="$OUT/win-core" cargo xwin build --quiet --locked \
            --manifest-path "$FIXTURE/Cargo.toml" --target "$wt" -p demo_core --release
        run 0 "cpus=x86-64-v4,x86-64-v3,x86-64-v2" "$inspect" cpulist "$OUT/win-launcher/$wt/release/demo.exe"
        run 0 "target=$wt" "$inspect" cpureq "$OUT/win-core/$wt/release/demo_core.dll"
        run 0 "cpu=x86-64-v3" "$inspect" cpureq "$OUT/win-core/$wt/release/demo_core.dll"
        # cargo-xwin builds with +crt-static: the record lists CPU features
        # only — exactly the Linux v3 core's.
        local win_features linux_features
        win_features="$("$inspect" cpureq "$OUT/win-core/$wt/release/demo_core.dll" | grep '^features=')"
        linux_features="$("$inspect" cpureq "$dir/lib/libdemo_core_x86-64-v3.so" | grep '^features=')"
        [ "$win_features" = "$linux_features" ] \
            || fail "the Windows v3 record differs from the Linux one: $win_features vs $linux_features"
        ok "windows: the PE launcher and core carry their records; the core's lists CPU features only"
    else
        skip "windows build: cargo-xwin not found"
    fi
}

fips() {
    command -v nm >/dev/null || fail "nm not found (install binutils)"
    command -v python3 >/dev/null || fail "python3 not found (the tamper step flips a bit with it)"
    echo "launcher-e2e: building a FIPS core (x86-64-v3; the AWS-LC FIPS module links statically)"
    RUSTFLAGS="" build "$OUT/launcher" demo --profile fips-tamper
    RUSTFLAGS="-C target-cpu=x86-64-v3" build "$OUT/fips-core" demo_core --profile fips-tamper --features fips
    local dir="$OUT/install-fips"
    rm -rf "$dir"
    mkdir -p "$dir/lib"
    cp "$OUT/launcher/$TARGET/fips-tamper/demo" "$dir/demo"
    local core="$dir/lib/libdemo_core_x86-64-v3.so"
    cp "$OUT/fips-core/$TARGET/fips-tamper/libdemo_core.so" "$core"
    scripts/verify-fips-binary.sh "$core" >/dev/null || fail "verify-fips-binary.sh refuses the core"
    # The CLI's port of the script (what verify applies to a FIPS
    # product's cores) agrees with it, both ways.
    run 0 "links only the pinned AWS-LC FIPS module" seaworthy fips-check "$core"
    run 1 "the pinned AWS-LC FIPS module is not linked" seaworthy fips-check "$dir/demo"
    ! scripts/verify-fips-binary.sh "$dir/demo" >/dev/null 2>&1 || fail "verify-fips-binary.sh accepts the launcher, which links no module"

    # Shipped cores are stripped (seaworthy layout runs strip): the
    # module's integrity check covers its text, which stripping leaves
    # alone, so a stripped FIPS core still passes its self-tests.
    local stripped_dir="$OUT/install-fips-stripped"
    rm -rf "$stripped_dir"
    mkdir -p "$stripped_dir/lib"
    cp "$dir/demo" "$stripped_dir/demo"
    cp "$core" "$stripped_dir/lib/libdemo_core_x86-64-v3.so"
    strip --strip-all "$stripped_dir/lib/libdemo_core_x86-64-v3.so"
    run 1 "no symbol table" seaworthy fips-check "$stripped_dir/lib/libdemo_core_x86-64-v3.so"
    run 0 "fips=ok" env SEAWORTHY_CORE=x86-64-v3 "$stripped_dir/demo"
    ok "fips: a stripped FIPS core (the shipped shape) still passes its self-tests"
    run 0 "fips=ok" env SEAWORTHY_CORE=x86-64-v3 "$dir/demo"
    ok "fips: the module inside a loaded per-CPU core passes its self-tests (verify-fips-binary.sh and seaworthy fips-check agree)"

    # Flip one bit in the middle of the module's text.
    # Read whole outputs first: an early-exiting reader would SIGPIPE the
    # producer, which pipefail reports as a failure.
    local symbols sections start end text_vaddr text_off
    symbols="$(nm "$core")"
    sections="$(readelf -SW "$core")"
    start="$(awk '/BORINGSSL_bcm_text_start$/ {print $1}' <<<"$symbols" | head -n1)"
    end="$(awk '/BORINGSSL_bcm_text_end$/ {print $1}' <<<"$symbols" | head -n1)"
    [ -n "$start" ] && [ -n "$end" ] || fail "no BORINGSSL_bcm_text_start/end symbols in $core"
    # The name's field moves with the index's width (`[ 9] .text`, `[10] .text`):
    # find it, then Type, Address, Off follow.
    read -r text_vaddr text_off < <(awk '{ for (i = 1; i <= NF; i++) if ($i == ".text") { print $(i + 2), $(i + 3); exit } }' <<<"$sections")
    [ -n "$text_vaddr" ] && [ -n "$text_off" ] || fail "no .text section header in $core"
    local mid=$(( (0x$start + 0x$end) / 2 ))
    local offset=$(( mid - 0x$text_vaddr + 0x$text_off ))
    python3 -I - "$core" "$offset" <<'PYEOF'
import sys
path, offset = sys.argv[1], int(sys.argv[2])
with open(path, "r+b") as f:
    f.seek(offset)
    byte = f.read(1)[0]
    f.seek(offset)
    f.write(bytes([byte ^ 0x01]))
PYEOF
    local out rc=0
    out="$(env SEAWORTHY_CORE=x86-64-v3 "$dir/demo" 2>&1)" || rc=$?
    [ "$rc" != 0 ] || fail "a tampered FIPS module still ran: $out"
    case "$out" in *core=*) fail "product code ran before the integrity test failed: $out" ;; esac
    case "$out" in *"FIPS integrity test failed"*) ;; *) fail "expected the FIPS integrity failure, got (exit $rc): $out" ;; esac
    ok "fips: one flipped bit in the module aborts the process (exit $rc) before any product code runs"
}

case "$mode" in
    selection) selection ;;
    fips) fips ;;
    all) selection; fips ;;
esac
echo "launcher-e2e: PASSED ($mode)"
