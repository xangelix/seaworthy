#!/usr/bin/env bash
# Drive the cargo-fuzz targets in fuzz/ (see fuzz/README.md).
#
#   scripts/fuzz.sh smoke             # every target for FUZZ_SMOKE_SECS (60 s), committed seeds
#                                     # only, nothing persisted; exit 1 on any crash
#   scripts/fuzz.sh nightly           # ~FUZZ_NIGHTLY_BUDGET_SECS (1800 s) spread across targets,
#                                     # growing a PERSISTED corpus under FUZZ_CORPUS_DIR,
#                                     # minimizing crashes, writing stats
#   scripts/fuzz.sh run <target> [s]  # one target locally (default 60 s), seeds + fuzz/work corpus
#   scripts/fuzz.sh list              # the target names
#   scripts/fuzz.sh build             # build every target (sanitizer build only)
#   scripts/fuzz.sh toolchain         # the pinned nightly
#
# Environment (all optional):
#   FUZZ_TOOLCHAIN          the nightly (default: the channel in fuzz/rust-toolchain.toml);
#                           installed with rustup when missing.
#   FUZZ_TARGETS            space-separated subset (default: every target).
#   FUZZ_SHARD              "i/n" (1-based): run every n-th target starting at i.
#   FUZZ_SMOKE_SECS         per-target smoke budget (default 60).
#   FUZZ_NIGHTLY_BUDGET_SECS total nightly budget, split evenly across targets (default 1800).
#   FUZZ_CORPUS_DIR         nightly's persisted corpus root, one subdirectory per target
#                           (default fuzz/corpus-nightly).
#   FUZZ_ARTIFACT_DIR       crash artifacts root (default fuzz/artifacts; <root>/<target>/crash-*,
#                           minimized as <root>/<target>/minimized-*).
#   FUZZ_LOG_DIR            per-target logs + stats.json (default fuzz/logs).
#   FUZZ_RSS_LIMIT_MB       libFuzzer -rss_limit_mb (default 2048).
#   FUZZ_TIMEOUT_SECS       libFuzzer per-input -timeout (default 25; a slow input is a crash).
#   FUZZ_JOBS               nightly: libFuzzer -fork=N workers per target (default 1).
#
# cargo-fuzz: the one on PATH when it is the pinned version, otherwise the
# pinned release binary from scripts/ci/install-tool.sh (SHA-256 verified).
#
# The fuzz crate is its OWN workspace (excluded from the root one): nothing here touches the
# stable build. Exit status: 0 = clean, 1 = at least one target crashed (all targets still run,
# so one invocation reports every crash), 2 = usage or tooling error.
set -uo pipefail

cd "$(git rev-parse --show-toplevel)" || exit 2
export PATH="$HOME/.cargo/bin:$PATH"

FUZZ_DIR="fuzz"
ARTIFACT_DIR="${FUZZ_ARTIFACT_DIR:-$FUZZ_DIR/artifacts}"
LOG_DIR="${FUZZ_LOG_DIR:-$FUZZ_DIR/logs}"
RSS_LIMIT="${FUZZ_RSS_LIMIT_MB:-2048}"
UNIT_TIMEOUT="${FUZZ_TIMEOUT_SECS:-25}"
CARGO_FUZZ_VERSION="0.13.2" # keep in step with scripts/ci/install-tool.sh

die() { echo "fuzz: $*" >&2; exit 2; }

is_uint() { [[ "$1" =~ ^[0-9]+$ ]]; }

pinned_toolchain() {
    sed -n 's/^channel *= *"\(.*\)"$/\1/p' "$FUZZ_DIR/rust-toolchain.toml"
}

TOOLCHAIN="${FUZZ_TOOLCHAIN:-$(pinned_toolchain)}"

# ---- tooling ---------------------------------------------------------------------------------

ensure_tools() {
    [ -n "$TOOLCHAIN" ] || die "no toolchain: set FUZZ_TOOLCHAIN or the channel in $FUZZ_DIR/rust-toolchain.toml"
    command -v rustup >/dev/null || die "rustup not found"
    if ! rustup run "$TOOLCHAIN" rustc --version >/dev/null 2>&1; then
        echo "fuzz: installing toolchain $TOOLCHAIN" >&2
        rustup toolchain install "$TOOLCHAIN" --profile minimal || die "cannot install $TOOLCHAIN"
    fi
    local have=""
    if command -v cargo-fuzz >/dev/null; then
        have="$(cargo-fuzz --version 2>/dev/null | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)"
    fi
    if [ "$have" != "$CARGO_FUZZ_VERSION" ]; then
        local tools_dir
        tools_dir="${SEAWORTHY_TOOLS_DIR:-${RUNNER_TEMP:+$RUNNER_TEMP/seaworthy-tools}}"
        tools_dir="${tools_dir:-$PWD/target/tools}"
        SEAWORTHY_TOOLS_DIR="$tools_dir" scripts/ci/install-tool.sh cargo-fuzz >&2 \
            || die "cannot install cargo-fuzz $CARGO_FUZZ_VERSION; install it and put it on PATH"
        export PATH="$tools_dir:$PATH"
    fi
}

# `--fuzz-dir` must precede any `--` (everything after it goes to libFuzzer).
cargo_fuzz() {
    local subcommand="$1"
    shift
    cargo "+$TOOLCHAIN" fuzz "$subcommand" --fuzz-dir "$FUZZ_DIR" "$@"
}

# The canonical list is the fuzz crate's [[bin]] entries.
all_targets() {
    sed -n '/^\[\[bin\]\]/,/^$/s/^name = "\(.*\)"$/\1/p' "$FUZZ_DIR/Cargo.toml"
}

selected_targets() {
    local targets
    if [ -n "${FUZZ_TARGETS:-}" ]; then
        targets="$FUZZ_TARGETS"
    else
        targets="$(all_targets | tr '\n' ' ')"
    fi
    local t
    for t in $targets; do
        all_targets | grep -qx -- "$t" || die "unknown target $t (scripts/fuzz.sh list)"
    done
    if [ -n "${FUZZ_SHARD:-}" ]; then
        local index="${FUZZ_SHARD%/*}" count="${FUZZ_SHARD#*/}" n=0
        is_uint "$index" && is_uint "$count" && [ "$index" -ge 1 ] && [ "$index" -le "$count" ] \
            || die "FUZZ_SHARD must be i/n with 1 <= i <= n (got $FUZZ_SHARD)"
        for t in $targets; do
            if [ $((n % count + 1)) -eq "$index" ]; then echo "$t"; fi
            n=$((n + 1))
        done
    else
        for t in $targets; do echo "$t"; done
    fi
}

# ---- one libFuzzer run -----------------------------------------------------------------------

# run_target <target> <seconds> <writable corpus dir> [extra libFuzzer args...]
# Seeds (fuzz/corpus/<target>) ride along read-only; new inputs land in the writable dir.
run_target() {
    local target="$1" secs="$2" work="$3"
    shift 3
    local seeds="$FUZZ_DIR/corpus/$target" dict="$FUZZ_DIR/dicts/$target.dict" log="$LOG_DIR/$target.log"
    mkdir -p "$work" "$ARTIFACT_DIR/$target" "$LOG_DIR"
    local args=(
        "-max_total_time=$secs"
        "-rss_limit_mb=$RSS_LIMIT"
        "-timeout=$UNIT_TIMEOUT"
        "-artifact_prefix=$ARTIFACT_DIR/$target/"
        "-print_final_stats=1"
    )
    [ -f "$dict" ] && args+=("-dict=$dict")
    echo "fuzz: $target, ${secs}s" >&2
    local status=0
    cargo_fuzz run "$target" "$work" "$seeds" --debug-assertions -- "${args[@]}" "$@" >"$log" 2>&1 \
        || status=$?
    local execs cov
    execs="$(grep -o 'stat::number_of_executed_units: *[0-9]*' "$log" | grep -o '[0-9]*$' | tail -1)"
    cov="$(grep -o 'cov: [0-9]*' "$log" | tail -1 | grep -o '[0-9]*')"
    printf '{"target":"%s","seconds":%s,"execs":%s,"cov":%s,"exit":%s}\n' \
        "$target" "$secs" "${execs:-0}" "${cov:-0}" "$status" >>"$LOG_DIR/stats.jsonl"
    if [ "$status" -ne 0 ]; then
        echo "fuzz: $target FAILED (exit $status); log: $log, artifacts: $ARTIFACT_DIR/$target/" >&2
        tail -n 40 "$log" >&2
    else
        echo "fuzz: $target ok, ${execs:-?} execs, cov ${cov:-?}" >&2
    fi
    return "$status"
}

# Minimize every not-yet-minimized crash of <target> (best effort).
minimize_crashes() {
    local target="$1" crash
    for crash in "$ARTIFACT_DIR/$target"/crash-* "$ARTIFACT_DIR/$target"/timeout-* \
        "$ARTIFACT_DIR/$target"/oom-* "$ARTIFACT_DIR/$target"/leak-*; do
        [ -f "$crash" ] || continue
        echo "fuzz: minimizing $crash" >&2
        cargo_fuzz tmin "$target" "$crash" --debug-assertions -- "-runs=4096" \
            "-exact_artifact_path=$ARTIFACT_DIR/$target/minimized-$(basename "$crash")" \
            >>"$LOG_DIR/$target.tmin.log" 2>&1 || true
    done
}

finish_stats() {
    [ -f "$LOG_DIR/stats.jsonl" ] || return 0
    { echo "["; sed '$!s/$/,/' "$LOG_DIR/stats.jsonl"; echo "]"; } >"$LOG_DIR/stats.json"
    echo "fuzz: stats in $LOG_DIR/stats.json" >&2
}

# ---- modes -----------------------------------------------------------------------------------

mode="${1:-}"
case "$mode" in
    list)
        all_targets
        ;;
    toolchain)
        echo "$TOOLCHAIN"
        ;;
    build)
        ensure_tools
        cargo_fuzz build --debug-assertions || exit 1
        ;;
    smoke)
        secs="${FUZZ_SMOKE_SECS:-60}"
        is_uint "$secs" && [ "$secs" -ge 1 ] || die "FUZZ_SMOKE_SECS must be a positive integer (got $secs)"
        mapfile -t targets < <(selected_targets)
        [ "${#targets[@]}" -gt 0 ] || die "no targets selected"
        ensure_tools
        rm -f "$LOG_DIR/stats.jsonl"
        cargo_fuzz build --debug-assertions || exit 1
        failed=()
        # The smoke corpus is throwaway: seeds are read-only, growth dies with the run.
        scratch="$(mktemp -d)"
        trap 'rm -rf "$scratch"' EXIT
        for target in "${targets[@]}"; do
            run_target "$target" "$secs" "$scratch/$target" || failed+=("$target")
        done
        finish_stats
        if [ "${#failed[@]}" -gt 0 ]; then
            echo "fuzz: smoke FAILED: ${failed[*]} (artifacts under $ARTIFACT_DIR/)" >&2
            exit 1
        fi
        echo "fuzz: smoke clean (${#targets[@]} targets x ${secs}s)" >&2
        ;;
    nightly)
        corpus_root="${FUZZ_CORPUS_DIR:-$FUZZ_DIR/corpus-nightly}"
        budget="${FUZZ_NIGHTLY_BUDGET_SECS:-1800}"
        jobs="${FUZZ_JOBS:-1}"
        is_uint "$budget" || die "FUZZ_NIGHTLY_BUDGET_SECS must be an integer (got $budget)"
        is_uint "$jobs" && [ "$jobs" -ge 1 ] || die "FUZZ_JOBS must be a positive integer (got $jobs)"
        mapfile -t targets < <(selected_targets)
        [ "${#targets[@]}" -gt 0 ] || die "no targets selected"
        ensure_tools
        secs=$((budget / ${#targets[@]}))
        [ "$secs" -ge 10 ] || secs=10
        extra=()
        [ "$jobs" -gt 1 ] && extra+=("-fork=$jobs" "-ignore_crashes=1")
        rm -f "$LOG_DIR/stats.jsonl"
        cargo_fuzz build --debug-assertions || exit 1
        failed=()
        for target in "${targets[@]}"; do
            if ! run_target "$target" "$secs" "$corpus_root/$target" "${extra[@]}"; then
                failed+=("$target")
            fi
            # A forked run can record crashes without failing the parent.
            if compgen -G "$ARTIFACT_DIR/$target/crash-*" >/dev/null \
                || compgen -G "$ARTIFACT_DIR/$target/timeout-*" >/dev/null \
                || compgen -G "$ARTIFACT_DIR/$target/oom-*" >/dev/null; then
                [[ " ${failed[*]} " == *" $target "* ]] || failed+=("$target")
            fi
            minimize_crashes "$target"
            # Keep the persisted corpus lean (merge-minimize in place).
            cargo_fuzz cmin "$target" "$corpus_root/$target" >>"$LOG_DIR/$target.cmin.log" 2>&1 || true
        done
        finish_stats
        if [ "${#failed[@]}" -gt 0 ]; then
            echo "fuzz: nightly found crashes in: ${failed[*]} (minimized under $ARTIFACT_DIR/)" >&2
            exit 1
        fi
        echo "fuzz: nightly clean (${#targets[@]} targets x ${secs}s)" >&2
        ;;
    run)
        target="${2:-}"
        secs="${3:-60}"
        [ -n "$target" ] || die "usage: scripts/fuzz.sh run <target> [seconds]"
        all_targets | grep -qx -- "$target" || die "unknown target $target (scripts/fuzz.sh list)"
        is_uint "$secs" && [ "$secs" -ge 1 ] || die "seconds must be a positive integer (got $secs)"
        ensure_tools
        rm -f "$LOG_DIR/stats.jsonl"
        run_target "$target" "$secs" "$FUZZ_DIR/work/$target"
        status=$?
        finish_stats
        exit "$status"
        ;;
    *)
        sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//' >&2
        exit 2
        ;;
esac
