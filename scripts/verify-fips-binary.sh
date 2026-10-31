#!/usr/bin/env bash
# scripts/verify-fips-binary.sh — prove a FIPS release binary links ONLY the
# pinned AWS-LC FIPS module.
#
# The Security Policy's static-link check (AWS-LC 3 Security Policy, #5314
# §11.1: `nm <app> | grep awslc_version_string` shows a `T` symbol)
# generalized into a gate, over the symbol table of an ELF (Linux) or
# Mach-O (macOS) binary:
#
#   1. the binary HAS a symbol table — a stripped binary FAILS (the check
#      would be vacuous): build it with `CARGO_PROFILE_RELEASE_STRIP=false`
#      (or `strip = false`), check it, then strip the shipped copy;
#   2. at least one `<prefix>*` symbol, and `<prefix>awslc_version_string`
#      DEFINED in text (`T`/`t`) — the module is statically linked;
#   3. ZERO non-FIPS AWS-LC symbols (`aws_lc_<maj>_<min>_<patch>_*`, the
#      aws-lc-sys prefix — a second, non-validated libcrypto);
#   4. ZERO `ring_core_*` symbols (ring);
#   5. ZERO FIPS-module symbols of ANOTHER version (`aws_lc_fips_*` without
#      the expected prefix — a module the pin does not name).
#
# The default prefix is the pinned sys crate's: aws-lc-fips-sys 0.14.3 →
# `aws_lc_fips_0_14_3_` (seaworthy_crypto::module::FIPS_SYMBOL_PREFIX; bump
# the two together). Standalone on purpose — bash, nm (binutils or llvm-nm;
# set NM to override), grep, awk — so applications run it over their own
# release binary. Windows and macOS FIPS builds link the module as a shared
# library, so a Windows or macOS core has none of it to find and is out of
# this script's scope: `seaworthy verify` checks those (on macOS over the
# core's symbol table, docs/fips.md). On macOS this script applies to the
# module's dylib itself.
#
# Usage (from the repository root, or anywhere):
#   scripts/verify-fips-binary.sh [--prefix aws_lc_fips_0_14_3_] BINARY
#   scripts/verify-fips-binary.sh [--prefix …] --nm-output FILE   # pre-captured `nm` output
#   scripts/verify-fips-binary.sh --self-test                     # the script's own tests
set -euo pipefail

DEFAULT_PREFIX="aws_lc_fips_0_14_3_"
NM="${NM:-nm}"

usage() {
    sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed -n 's/^# \{0,1\}//p' >&2
    exit 2
}

# check_symbols PREFIX < nm-output → prints findings, exit 0 = pass, 1 = fail.
check_symbols() {
    local prefix="$1" symbols
    symbols="$(cat)"
    # Mach-O prepends `_` to C symbols; strip one so both formats match.
    local names
    names="$(printf '%s\n' "$symbols" | awk 'NF >= 2 { name = $NF; sub(/^_/, "", name); print $(NF-1), name }')"
    local total fips version_line non_fips ring other_fips rc=0
    total="$(printf '%s\n' "$names" | grep -c . || true)"
    if [ "$total" -eq 0 ]; then
        echo "FAIL: no symbols — the binary is stripped (or not an object file); build it with" \
            "CARGO_PROFILE_RELEASE_STRIP=false, check it, then strip the shipped copy"
        return 1
    fi
    fips="$(printf '%s\n' "$names" | awk -v p="$prefix" 'index($2, p) == 1' | grep -c . || true)"
    version_line="$(printf '%s\n' "$names" | awk -v s="${prefix}awslc_version_string" '$2 == s && ($1 == "T" || $1 == "t")' | head -n1)"
    non_fips="$(printf '%s\n' "$names" | awk '$2 ~ /^aws_lc_[0-9]+_[0-9]+_[0-9]+_/' | awk '{print $2}' | sort -u)"
    ring="$(printf '%s\n' "$names" | awk '$2 ~ /^ring_core_/' | awk '{print $2}' | sort -u)"
    other_fips="$(printf '%s\n' "$names" | awk -v p="$prefix" '$2 ~ /^aws_lc_fips_/ && index($2, p) != 1' | awk '{print $2}' | sort -u)"

    if [ "$fips" -eq 0 ]; then
        echo "FAIL: no ${prefix}* symbols — the pinned AWS-LC FIPS module is not linked"
        rc=1
    else
        echo "ok:   ${fips} ${prefix}* symbols"
    fi
    if [ -z "$version_line" ]; then
        echo "FAIL: ${prefix}awslc_version_string is not a defined text symbol (SP §11.1 static-link check)"
        rc=1
    else
        echo "ok:   ${prefix}awslc_version_string is defined in text (statically linked)"
    fi
    if [ -n "$non_fips" ]; then
        echo "FAIL: $(printf '%s\n' "$non_fips" | grep -c .) non-FIPS AWS-LC (aws-lc-sys) symbols, e.g.:"
        printf '%s\n' "$non_fips" | head -n5 | sed 's/^/        /'
        rc=1
    else
        echo "ok:   zero non-FIPS aws_lc_<version>_* symbols"
    fi
    if [ -n "$ring" ]; then
        echo "FAIL: $(printf '%s\n' "$ring" | grep -c .) ring symbols, e.g.:"
        printf '%s\n' "$ring" | head -n5 | sed 's/^/        /'
        rc=1
    else
        echo "ok:   zero ring_core_* symbols"
    fi
    if [ -n "$other_fips" ]; then
        echo "FAIL: AWS-LC FIPS symbols of a version other than ${prefix}, e.g.:"
        printf '%s\n' "$other_fips" | head -n5 | sed 's/^/        /'
        rc=1
    else
        echo "ok:   no other AWS-LC FIPS module version"
    fi
    return "$rc"
}

self_test() {
    local dir rc=0
    dir="$(mktemp -d)"
    trap 'rm -rf "$dir"' RETURN
    local p="$DEFAULT_PREFIX"
    # Each fixture: name, expected result (0 pass / 1 fail), nm lines.
    printf '%s\n' "0000000000001000 T ${p}awslc_version_string" "0000000000001010 T ${p}RAND_bytes" \
        "0000000000002000 T main" "                 U memcpy" > "$dir/clean"
    printf '%s\n' "0000000000001000 T _${p}awslc_version_string" "0000000000001010 T _${p}FIPS_mode" > "$dir/macho"
    printf '' > "$dir/stripped"
    printf '%s\n' "0000000000002000 T main" > "$dir/no_module"
    printf '%s\n' "0000000000001000 D ${p}awslc_version_string" "0000000000001010 T ${p}RAND_bytes" > "$dir/version_not_text"
    printf '%s\n' "0000000000001000 T ${p}awslc_version_string" "0000000000003000 T aws_lc_0_45_0_EVP_sha256" > "$dir/non_fips"
    printf '%s\n' "0000000000001000 T ${p}awslc_version_string" "0000000000003000 T ring_core_0_17_14__x25519" > "$dir/ring"
    printf '%s\n' "0000000000001000 T ${p}awslc_version_string" "0000000000003000 T aws_lc_fips_0_13_9_SHA256" > "$dir/other_fips"
    local case expected got
    for case in clean:0 macho:0 stripped:1 no_module:1 version_not_text:1 non_fips:1 ring:1 other_fips:1; do
        expected="${case#*:}"
        case="${case%%:*}"
        got=0
        check_symbols "$p" < "$dir/$case" > "$dir/$case.out" || got=$?
        if [ "$got" -eq "$expected" ]; then
            echo "ok:   self-test ${case} (exit ${got})"
        else
            echo "FAIL: self-test ${case}: expected exit ${expected}, got ${got}"
            sed 's/^/        /' "$dir/$case.out"
            rc=1
        fi
    done
    return "$rc"
}

prefix="$DEFAULT_PREFIX"
nm_output=""
binary=""
while [ $# -gt 0 ]; do
    case "$1" in
        --prefix) prefix="${2:?--prefix needs a value}"; shift 2 ;;
        --nm-output) nm_output="${2:?--nm-output needs a file}"; shift 2 ;;
        --self-test) self_test; exit $? ;;
        -h|--help) usage ;;
        -*) echo "unknown option: $1" >&2; usage ;;
        *) binary="$1"; shift ;;
    esac
done

if [ -n "$nm_output" ]; then
    echo "verify-fips-binary: ${nm_output} (pre-captured nm output), expecting ${prefix}*"
    check_symbols "$prefix" < "$nm_output"
    exit $?
fi
[ -n "$binary" ] || usage
[ -f "$binary" ] || { echo "verify-fips-binary: no such file: $binary" >&2; exit 2; }
command -v "$NM" >/dev/null 2>&1 || { echo "verify-fips-binary: $NM not found (binutils or llvm-nm; set NM)" >&2; exit 2; }
echo "verify-fips-binary: ${binary}, expecting ${prefix}*"
"$NM" "$binary" 2>/dev/null | check_symbols "$prefix"
