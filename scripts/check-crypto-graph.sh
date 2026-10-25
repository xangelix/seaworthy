#!/usr/bin/env bash
# scripts/check-crypto-graph.sh — the crypto dependency-graph guard. One
# crypto stack: AWS-LC through seaworthy-crypto. Over the feature-RESOLVED
# graph (`cargo tree`, host platform, every edge kind) of each configuration
# below, it fails when:
#
#   1. a banned crate is anywhere in the graph: `ring`, `openssl`,
#      `openssl-sys`, `native-tls`, `boring-sys`, `blake3` (a second crypto
#      or TLS backend, outside the FIPS module boundary; the rule is the
#      regression guard);
#   2. a workspace member depends DIRECTLY on `ring`, `openssl`,
#      `openssl-sys`, `native-tls`, `boring-sys` or `aws-lc-sys`, or on
#      `aws-lc-rs` / `aws-lc-fips-sys` other than through seaworthy-crypto
#      (only seaworthy-crypto touches AWS-LC);
#   3. `aws-lc-sys` (the NON-FIPS AWS-LC) has any parent other than
#      `aws-lc-rs` — anything else could link a second, non-validated
#      libcrypto next to the FIPS module;
#   4. `aws-lc-fips-sys` has any parent other than `aws-lc-rs` and
#      seaworthy-crypto.
#
# Configurations (each one `cargo tree`, about a second; no build): the
# workspace with default features, with every non-FIPS feature of every
# member, and with `seaworthy-crypto/fips`. In the `fips` configuration
# `aws-lc-sys` is STILL compiled — rustls's `aws_lc_rs` feature (which
# `rustls/fips` implies) enables `aws-lc-rs/aws-lc-sys` unconditionally —
# but never linked (aws-lc-rs selects `aws-lc-fips-sys` under `fips`); rule 3
# keeps it that way, and scripts/check-fips-binary.sh proves it on the
# release binary. See docs/fips.md.
#
# Needs cargo and python3. Runs from the repository root (or anywhere: it
# finds the root from its own path).
#
# Usage: scripts/check-crypto-graph.sh            (every configuration)
#        scripts/check-crypto-graph.sh --self-test (the rule engine's own tests)
set -euo pipefail

if ! command -v python3 >/dev/null 2>&1; then
    echo "error: python3 not found — the crypto graph guard cannot run" >&2
    exit 1
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export SEAWORTHY_GRAPH_ROOT="$root"
exec python3 - "$@" <<'PY'
import json
import os
import subprocess
import sys

BANNED_ANYWHERE = ["ring", "openssl", "openssl-sys", "native-tls", "boring-sys", "blake3"]
BANNED_DIRECT = BANNED_ANYWHERE + ["aws-lc-sys"]
AWS_LC_DIRECT_OWNER = "seaworthy-crypto"
AWS_LC_DIRECT = ["aws-lc-rs", "aws-lc-fips-sys"]
# Reviewed, configuration-scoped exceptions to BANNED_ANYWHERE: (label,
# crate) → (the parents it may have there, the reason). Must stay real: an
# entry whose crate is gone from that configuration FAILS (stale), and any
# other parent fails as usual. Empty.
ALLOWLIST = {}
SOLE_PARENTS = {
    "aws-lc-sys": {"aws-lc-rs"},
    "aws-lc-fips-sys": {"aws-lc-rs", "seaworthy-crypto"},
}


def check(graph, label):
    """Apply the rules to one parsed graph; return (findings, present crates).

    `graph` = (members, edges): workspace member names, and the set of
    (parent, child) name pairs of the feature-resolved graph."""
    members, edges = graph
    present = set(members) | {c for _, c in edges} | {p for p, _ in edges}
    findings = []
    for banned in BANNED_ANYWHERE:
        allowed = ALLOWLIST.get((label, banned))
        if banned in present:
            parents = sorted({p for p, c in edges if c == banned})
            if allowed is not None and set(parents) <= allowed[0]:
                print(f"  allowlisted in {label}: `{banned}` via {', '.join(parents)} — {allowed[1]}")
                continue
            findings.append(f"[{label}] banned crate `{banned}` is in the graph "
                            f"(pulled in by: {', '.join(parents) or '?'})")
        elif allowed is not None:
            findings.append(f"[{label}] stale allowlist entry: `{banned}` is no longer in "
                            f"this graph — remove it from ALLOWLIST")
    for member, dep in sorted(edges):
        if member not in members:
            continue
        if dep in BANNED_DIRECT:
            findings.append(f"[{label}] workspace member `{member}` depends directly "
                            f"on banned `{dep}`")
        if dep in AWS_LC_DIRECT and member != AWS_LC_DIRECT_OWNER:
            findings.append(f"[{label}] workspace member `{member}` depends directly on "
                            f"`{dep}` — only {AWS_LC_DIRECT_OWNER} touches AWS-LC")
    for crate, allowed in SOLE_PARENTS.items():
        parents = {p for p, c in edges if c == crate}
        extra = sorted(parents - allowed)
        if extra:
            findings.append(f"[{label}] `{crate}` has parent(s) {', '.join(extra)} — only "
                            f"{', '.join(sorted(allowed))} may depend on it")
    return findings, present


def resolved_graph(manifest_dir, features):
    """The feature-resolved graph (`cargo tree`, host platform — the
    resolver-2 view the build uses; `cargo metadata`'s resolve is not
    feature-precise), every edge kind, as (members, edges)."""
    cmd = ["cargo", "tree", "--workspace", "-e", "normal,build,dev",
           "--prefix", "depth", "-f", "{p}"]
    if features:
        cmd += ["--features", features]
    out = subprocess.run(cmd, check=True, capture_output=True, text=True, cwd=manifest_dir)
    members, edges, stack = set(), set(), []
    for line in out.stdout.splitlines():
        digits = len(line) - len(line.lstrip("0123456789"))
        if digits == 0 or not line[digits:].strip():
            continue
        depth = int(line[:digits])
        name = line[digits:].split()[0]
        del stack[depth:]
        if depth == 0:
            members.add(name)
        elif stack:
            edges.add((stack[-1], name))
        stack.append(name)
    return members, edges


def non_fips_features(root):
    """Every feature of every workspace member except the FIPS switches, as
    `member/feature` (a FIPS feature changes the backend, so it gets its own
    configuration)."""
    out = subprocess.run(["cargo", "metadata", "--no-deps", "--format-version", "1"],
                         check=True, capture_output=True, text=True, cwd=root)
    features = []
    for package in json.loads(out.stdout)["packages"]:
        for feature in sorted(package["features"]):
            if feature != "default" and "fips" not in feature:
                features.append(f"{package['name']}/{feature}")
    return ",".join(features)


def self_test():
    def doc(edges, members=("app",)):
        return set(members), set(edges)
    cases = [
        ("clean", doc([("app", "seaworthy-crypto"), ("seaworthy-crypto", "aws-lc-rs"),
                       ("seaworthy-crypto", "aws-lc-fips-sys"), ("aws-lc-rs", "aws-lc-sys"),
                       ("aws-lc-rs", "aws-lc-fips-sys")], members=("app", "seaworthy-crypto")), 0),
        ("ring anywhere", doc([("app", "quinn"), ("quinn", "ring")]), 1),
        ("openssl-sys anywhere", doc([("app", "reqwest"), ("reqwest", "openssl-sys")]), 1),
        ("direct aws-lc-sys", doc([("app", "aws-lc-sys")]), 2),
        ("direct aws-lc-rs outside seaworthy-crypto", doc([("app", "aws-lc-rs")]), 1),
        ("second aws-lc-sys parent", doc([("app", "x"), ("x", "aws-lc-sys"),
                                          ("aws-lc-rs", "aws-lc-sys")]), 1),
        ("foreign aws-lc-fips-sys parent", doc([("app", "y"), ("y", "aws-lc-fips-sys")]), 1),
    ]
    failed = 0
    for name, document, expected in cases:
        findings, _ = check(document, name)
        if len(findings) == expected:
            print(f"ok:   self-test {name} ({expected} finding(s))")
        else:
            failed += 1
            print(f"FAIL: self-test {name}: expected {expected} finding(s), got {findings}")
    return 1 if failed else 0


def main(argv):
    if argv[1:] == ["--self-test"]:
        return self_test()
    if argv[1:]:
        print(f"usage: {argv[0]} [--self-test]", file=sys.stderr)
        return 2
    root = os.environ["SEAWORTHY_GRAPH_ROOT"]
    configurations = [
        ("workspace/default", root, ""),
        ("workspace/all-non-fips", root, non_fips_features(root)),
        ("workspace/fips", root, f"{AWS_LC_DIRECT_OWNER}/fips"),
    ]
    findings = []
    for label, manifest_dir, features in configurations:
        try:
            graph = resolved_graph(manifest_dir, features)
        except subprocess.CalledProcessError as error:
            findings.append(f"[{label}] cargo tree failed: {error.stderr.strip()[:400]}")
            continue
        found, present = check(graph, label)
        findings += found
        note = ""
        if label == "workspace/fips" and "aws-lc-sys" in present:
            note = " (aws-lc-sys compiled, never linked: rustls's aws_lc_rs feature enables it)"
        print(f"  {label}: {len(present)} crates, {len(found)} finding(s){note}")
    if findings:
        print("crypto graph guard FAILED:")
        for finding in findings:
            print(f"  - {finding}")
        return 1
    print("crypto graph guard: ok")
    return 0


sys.exit(main(sys.argv))
PY
