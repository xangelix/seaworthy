#!/usr/bin/env bash
# scripts/verify-fips-binary.sh — prove a FIPS release binary links ONE
# AWS-LC FIPS module, of a release on the FIPS allowlist, and nothing else.
#
# The Security Policy's static-link check (AWS-LC 3 Security Policy, #5314
# §11.1: `nm <app> | grep awslc_version_string` shows a `T` symbol)
# generalized into a gate, over the symbol table of an ELF (Linux) or
# Mach-O (macOS) binary:
#
#   1. the binary HAS a symbol table — a stripped binary FAILS (the check
#      would be vacuous): build it with `CARGO_PROFILE_RELEASE_STRIP=false`
#      (or `strip = false`), check it, then strip the shipped copy;
#   2. the symbols of exactly ONE AWS-LC FIPS module
#      (`aws_lc_fips_<major>_<minor>_<patch>_*`, the aws-lc-fips-sys
#      release's prefix), and no other `aws_lc_fips_*` symbol;
#   3. that release is on the FIPS allowlist (and, with `--module` or
#      `--prefix`, the one named: an application's declared module);
#   4. `<prefix>awslc_version_string` DEFINED in text (`T`/`t`) — the module
#      is statically linked;
#   5. ZERO non-FIPS AWS-LC symbols (`aws_lc_<maj>_<min>_<patch>_*`, the
#      aws-lc-sys prefix — a second, non-validated libcrypto);
#   6. ZERO `ring_core_*` symbols (ring).
#
# It reports the release it found. The allowlist is
# crates/seaworthy-crypto/fips-allowlist.txt (its `module` lines; the one
# source of truth, which seaworthy-crypto also enforces at build time and at
# startup); `--allowlist FILE` reads another copy. Standalone otherwise —
# bash, nm (binutils or llvm-nm; set NM to override), grep, awk — so
# applications run it over their own release binary. Windows and macOS FIPS
# builds link the module as a shared library, so a Windows or macOS core has
# none of it to find and is out of this script's scope: `seaworthy verify`
# checks those (on macOS over the core's symbol table, docs/fips.md). On
# macOS this script applies to the module's dylib itself.
#
# Usage (from the repository root, or anywhere):
#   scripts/verify-fips-binary.sh [--allowlist FILE] [--module 0.14.4 | --prefix aws_lc_fips_0_14_4_] BINARY
#   scripts/verify-fips-binary.sh [options] --nm-output FILE    # pre-captured `nm` output
#   scripts/verify-fips-binary.sh --self-test                   # the script's own tests
set -euo pipefail

DEFAULT_ALLOWLIST="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/crates/seaworthy-crypto/fips-allowlist.txt"
NM="${NM:-nm}"

usage() {
    sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed -n 's/^# \{0,1\}//p' >&2
    exit 2
}

# allowed_prefixes FILE → one symbol prefix per allowlisted aws-lc-fips-sys
# release (`module <release> <module> <branch>` lines).
allowed_prefixes() {
    awk '$1 == "module" && NF == 4 && $2 ~ /^[0-9]+\.[0-9]+\.[0-9]+$/ {
        prefix = $2; gsub(/\./, "_", prefix); print "aws_lc_fips_" prefix "_"
    }' "$1"
}

# release_of PREFIX → `0.14.4` for `aws_lc_fips_0_14_4_`.
release_of() {
    local release="${1#aws_lc_fips_}"
    release="${release%_}"
    printf '%s\n' "${release//_/.}"
}

# check_symbols ALLOWED EXPECTED < nm-output → prints findings; exit 0 =
# pass, 1 = fail. ALLOWED: newline-separated prefixes; EXPECTED: one prefix,
# or empty for any allowlisted one.
check_symbols() {
    local allowed="$1" expected="$2" symbols
    symbols="$(cat)"
    # Mach-O prepends `_` to C symbols; strip one so both formats match.
    local names
    names="$(printf '%s\n' "$symbols" | awk 'NF >= 2 { name = $NF; sub(/^_/, "", name); print $(NF-1), name }')"
    local total modules count prefix fips version_line non_fips ring stray rc=0
    total="$(printf '%s\n' "$names" | grep -c . || true)"
    if [ "$total" -eq 0 ]; then
        echo "FAIL: no symbols — the binary is stripped (or not an object file); build it with" \
            "CARGO_PROFILE_RELEASE_STRIP=false, check it, then strip the shipped copy"
        return 1
    fi
    modules="$(printf '%s\n' "$names" | awk '{ print $2 }' \
        | sed -n 's/^\(aws_lc_fips_[0-9][0-9]*_[0-9][0-9]*_[0-9][0-9]*_\).*/\1/p' | sort -u)"
    count="$(printf '%s\n' "$modules" | grep -c . || true)"
    if [ "$count" -eq 0 ]; then
        echo "FAIL: no aws_lc_fips_<release>_* symbols — no AWS-LC FIPS module is linked"
        return 1
    fi
    if [ "$count" -gt 1 ]; then
        echo "FAIL: the symbols of ${count} AWS-LC FIPS modules — one module, of one release:"
        printf '%s\n' "$modules" | sed 's/^/        /'
        return 1
    fi
    prefix="$modules"
    fips="$(printf '%s\n' "$names" | awk -v p="$prefix" 'index($2, p) == 1' | grep -c . || true)"
    echo "ok:   one AWS-LC FIPS module: aws-lc-fips-sys $(release_of "$prefix") (${fips} ${prefix}* symbols)"
    if ! printf '%s\n' "$allowed" | grep -qxF -- "$prefix"; then
        echo "FAIL: aws-lc-fips-sys $(release_of "$prefix") is not on the FIPS allowlist" \
            "($(printf '%s\n' "$allowed" | while read -r p; do [ -n "$p" ] && printf '%s ' "$(release_of "$p")"; done | sed 's/ $//'))"
        rc=1
    else
        echo "ok:   aws-lc-fips-sys $(release_of "$prefix") is on the FIPS allowlist"
    fi
    if [ -n "$expected" ]; then
        if [ "$prefix" != "$expected" ]; then
            echo "FAIL: the module is aws-lc-fips-sys $(release_of "$prefix"), not the declared $(release_of "$expected") (${expected}*)"
            rc=1
        else
            echo "ok:   it is the declared module (${expected}*)"
        fi
    fi
    version_line="$(printf '%s\n' "$names" | awk -v s="${prefix}awslc_version_string" '$2 == s && ($1 == "T" || $1 == "t")' | head -n1)"
    if [ -z "$version_line" ]; then
        echo "FAIL: ${prefix}awslc_version_string is not a defined text symbol (SP §11.1 static-link check)"
        rc=1
    else
        echo "ok:   ${prefix}awslc_version_string is defined in text (statically linked)"
    fi
    non_fips="$(printf '%s\n' "$names" | awk '$2 ~ /^aws_lc_[0-9]+_[0-9]+_[0-9]+_/' | awk '{print $2}' | sort -u)"
    if [ -n "$non_fips" ]; then
        echo "FAIL: $(printf '%s\n' "$non_fips" | grep -c .) non-FIPS AWS-LC (aws-lc-sys) symbols, e.g.:"
        printf '%s\n' "$non_fips" | head -n5 | sed 's/^/        /'
        rc=1
    else
        echo "ok:   zero non-FIPS aws_lc_<version>_* symbols"
    fi
    ring="$(printf '%s\n' "$names" | awk '$2 ~ /^ring_core_/' | awk '{print $2}' | sort -u)"
    if [ -n "$ring" ]; then
        echo "FAIL: $(printf '%s\n' "$ring" | grep -c .) ring symbols, e.g.:"
        printf '%s\n' "$ring" | head -n5 | sed 's/^/        /'
        rc=1
    else
        echo "ok:   zero ring_core_* symbols"
    fi
    stray="$(printf '%s\n' "$names" | awk -v p="$prefix" '$2 ~ /^aws_lc_fips_/ && index($2, p) != 1' | awk '{print $2}' | sort -u)"
    if [ -n "$stray" ]; then
        echo "FAIL: aws_lc_fips_* symbols outside the module's ${prefix}*, e.g.:"
        printf '%s\n' "$stray" | head -n5 | sed 's/^/        /'
        rc=1
    else
        echo "ok:   no other AWS-LC FIPS module symbols"
    fi
    return "$rc"
}

self_test() {
    local dir rc=0
    dir="$(mktemp -d)"
    trap 'rm -rf "$dir"' RETURN
    printf '%s\n' "# a fixture allowlist" "module 0.14.3 4.2.0 4" "module 0.14.4 4.2.0 4" "" \
        "aws-lc-rs 1.19.0 0.14" > "$dir/allowlist"
    local allowed p="aws_lc_fips_0_14_4_" q="aws_lc_fips_0_14_3_" u="aws_lc_fips_0_14_9_"
    allowed="$(allowed_prefixes "$dir/allowlist")"
    if [ "$allowed" != "$(printf '%s\n' "$q" "$p")" ]; then
        echo "FAIL: self-test allowlist parse: got $(printf '%q' "$allowed")"
        rc=1
    fi
    # Each fixture: nm lines.
    printf '%s\n' "0000000000001000 T ${p}awslc_version_string" "0000000000001010 T ${p}RAND_bytes" \
        "0000000000002000 T main" "                 U memcpy" > "$dir/clean"
    printf '%s\n' "0000000000001000 T ${q}awslc_version_string" "0000000000001010 T ${q}RAND_bytes" > "$dir/older"
    printf '%s\n' "0000000000001000 T _${p}awslc_version_string" "0000000000001010 T _${p}FIPS_mode" > "$dir/macho"
    printf '' > "$dir/stripped"
    printf '%s\n' "0000000000002000 T main" > "$dir/no_module"
    printf '%s\n' "0000000000001000 D ${p}awslc_version_string" "0000000000001010 T ${p}RAND_bytes" > "$dir/version_not_text"
    printf '%s\n' "0000000000001000 T ${p}awslc_version_string" "0000000000003000 T aws_lc_0_45_0_EVP_sha256" > "$dir/non_fips"
    printf '%s\n' "0000000000001000 T ${p}awslc_version_string" "0000000000003000 T ring_core_0_17_14__x25519" > "$dir/ring"
    printf '%s\n' "0000000000001000 T ${p}awslc_version_string" "0000000000003000 T ${q}SHA256" > "$dir/two_modules"
    printf '%s\n' "0000000000001000 T ${p}awslc_version_string" "0000000000003000 T aws_lc_fips_0_13_9_SHA256" > "$dir/other_fips"
    printf '%s\n' "0000000000001000 T ${u}awslc_version_string" "0000000000001010 T ${u}RAND_bytes" > "$dir/unlisted"
    printf '%s\n' "0000000000001000 T ${p}awslc_version_string" "0000000000003000 T aws_lc_fips_shim" > "$dir/stray"
    # case:expected-exit[:declared prefix]
    local case expected declared got name
    for case in clean:0 older:0 macho:0 stripped:1 no_module:1 version_not_text:1 non_fips:1 ring:1 \
        two_modules:1 other_fips:1 unlisted:1 stray:1 "clean:0:${p}" "older:1:${p}" "clean:1:${q}" \
        "unlisted:1:${u}"; do
        name="${case%%:*}"
        expected="${case#*:}"
        declared=""
        if [ "${expected#*:}" != "$expected" ]; then
            declared="${expected#*:}"
            expected="${expected%%:*}"
        fi
        got=0
        check_symbols "$allowed" "$declared" < "$dir/$name" > "$dir/$name.out" || got=$?
        if [ "$got" -eq "$expected" ]; then
            echo "ok:   self-test ${name}${declared:+ (declared ${declared})} (exit ${got})"
        else
            echo "FAIL: self-test ${name}${declared:+ (declared ${declared})}: expected exit ${expected}, got ${got}"
            sed 's/^/        /' "$dir/$name.out"
            rc=1
        fi
    done
    # The repository's allowlist parses, and accepts the module its newest
    # entry names.
    local newest
    newest="$(allowed_prefixes "$DEFAULT_ALLOWLIST" | tail -n1)"
    if [ -z "$newest" ]; then
        echo "FAIL: self-test: ${DEFAULT_ALLOWLIST} names no module"
        rc=1
    else
        got=0
        sed "s/${p}/${newest}/g" "$dir/clean" \
            | check_symbols "$(allowed_prefixes "$DEFAULT_ALLOWLIST")" "" > "$dir/default.out" || got=$?
        if [ "$got" -eq 0 ]; then
            echo "ok:   self-test the repository's allowlist accepts ${newest}*"
        else
            echo "FAIL: self-test the repository's allowlist refuses its own ${newest}*"
            sed 's/^/        /' "$dir/default.out"
            rc=1
        fi
    fi
    return "$rc"
}

allowlist="$DEFAULT_ALLOWLIST"
expected=""
nm_output=""
binary=""
while [ $# -gt 0 ]; do
    case "$1" in
        --allowlist) allowlist="${2:?--allowlist needs a file}"; shift 2 ;;
        --module) expected="aws_lc_fips_${2:?--module needs a release}_"; expected="${expected//./_}"; shift 2 ;;
        --prefix) expected="${2:?--prefix needs a value}"; shift 2 ;;
        --nm-output) nm_output="${2:?--nm-output needs a file}"; shift 2 ;;
        --self-test) self_test; exit $? ;;
        -h|--help) usage ;;
        -*) echo "unknown option: $1" >&2; usage ;;
        *) binary="$1"; shift ;;
    esac
done

[ -f "$allowlist" ] || { echo "verify-fips-binary: no allowlist at ${allowlist} (--allowlist FILE)" >&2; exit 2; }
allowed="$(allowed_prefixes "$allowlist")"
[ -n "$allowed" ] || { echo "verify-fips-binary: ${allowlist} names no module" >&2; exit 2; }
want="${expected:-any module on the FIPS allowlist}"

if [ -n "$nm_output" ]; then
    echo "verify-fips-binary: ${nm_output} (pre-captured nm output), expecting ${want}"
    check_symbols "$allowed" "$expected" < "$nm_output"
    exit $?
fi
[ -n "$binary" ] || usage
[ -f "$binary" ] || { echo "verify-fips-binary: no such file: $binary" >&2; exit 2; }
command -v "$NM" >/dev/null 2>&1 || { echo "verify-fips-binary: $NM not found (binutils or llvm-nm; set NM)" >&2; exit 2; }
echo "verify-fips-binary: ${binary}, expecting ${want}"
"$NM" "$binary" 2>/dev/null | check_symbols "$allowed" "$expected"
