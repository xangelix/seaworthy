#!/usr/bin/env bash
# scripts/check-tls-construction.sh: every TLS configuration is built in the
# crypto crate (crates/seaworthy-crypto), and every outbound HTTP client takes
# a configuration built there.
#
# The crypto crate owns the TLS policy (provider, protocol versions, key
# exchange groups, cipher suites, certificate verification) and the provider
# that the FIPS build vouches for. A configuration built anywhere else can
# silently fall back to a library's own provider or verifier, or to whatever
# Cargo feature unification happens to select. This guard fails on:
#
#   R1  a cryptography provider chosen or installed outside the crypto crate,
#       tests included: `aws_lc_rs::default_provider()`, any `crypto::ring`
#       path, `CryptoProvider::install_default` / `.install_default()`;
#   R2  a rustls configuration built outside the crypto crate:
#       `ClientConfig::builder*(` / `ServerConfig::builder*(`, qualified with
#       `rustls::` or not;
#   R3  a rustls-platform-verifier configuration or verifier built outside
#       the crypto crate: `with_platform_verifier(` (method or associated
#       function), any `rustls_platform_verifier::` path;
#   R4  a reqwest client with its own TLS: `reqwest::get(`,
#       `reqwest::Client::new()` (and `blocking::`), and a
#       `reqwest::Client::builder()` / `reqwest::ClientBuilder::new()` in a
#       file that never calls `use_preconfigured_tls` (file-level: the
#       builder chain may span helpers).
#
# R2-R4 scan production Rust only: `tests/`, `examples/`, `benches/`,
# `build.rs`, `#[cfg(test)]` / `#[test]` items, the files of
# `#[cfg(test)] mod x;` declarations and files opening with `#![cfg(test)]`
# are skipped. Comments and string literals never match. The fuzz crate
# (`fuzz/`) is test code too. Exceptions live in the allowlist
# (scripts/tls-construction-allowlist.txt; `--allowlist FILE` overrides),
# one per line, ` | `-separated, `#` comments:
#
#   site <path> | <fragment> | <reason>   a match whose line, in <path>,
#                                         contains <fragment>
#   path <prefix> | <reason>              every match under a path prefix
#
# Every entry needs a reason and must match something (a stale entry fails).
#
# Usage: scripts/check-tls-construction.sh [--root DIR] [--allowlist FILE]
#                                          [--crypto-crate PATH]
#   --crypto-crate  the one directory allowed to build TLS configurations
#                   (default crates/seaworthy-crypto)
#   Exit 0 = clean, 1 = a violation or a bad allowlist, 2 = cannot run.
set -euo pipefail

if ! command -v python3 >/dev/null 2>&1; then
    echo "error: python3 not found; the TLS-construction check cannot run" >&2
    exit 2
fi

exec python3 -I - "$@" <<'PYEOF'
import os
import re
import subprocess
import sys

R1 = re.compile(
    r'\baws_lc_rs\s*::\s*default_provider\s*\('
    r'|\bcrypto\s*::\s*ring\b'
    r'|\bCryptoProvider\s*::\s*install_default\s*\('
    r'|\.\s*install_default\s*\(\s*\)'
)
R2 = re.compile(
    r'\b(?:rustls\s*::\s*)?(?:ClientConfig|ServerConfig)\s*::\s*'
    r'builder(?:_with_provider|_with_protocol_versions|_with_details)?\s*\('
)
R3 = re.compile(r'(?:\.|::)\s*with_platform_verifier\s*\(|\brustls_platform_verifier\s*::')
R4_ALWAYS = re.compile(r'\breqwest\s*::\s*(?:blocking\s*::\s*)?(?:Client\s*::\s*new\s*\(|get\s*\()')
R4_BUILDER = re.compile(
    r'\breqwest\s*::\s*(?:blocking\s*::\s*)?(?:Client\s*::\s*builder|ClientBuilder\s*::\s*new)\s*\('
)
NON_PRODUCTION_SEGMENTS = ("/tests/", "/examples/", "/benches/")
NON_PRODUCTION_PREFIXES = ("fuzz/",)
CFG_TEST_ATTR = re.compile(r'#\[cfg\((?:all\()?test\b')
TEST_FN_ATTR = re.compile(r'#\[(?:tokio::)?test\b')
TEST_MOD_DECL = re.compile(
    r'#\[cfg\((?:all\()?test\b[^\]]*\]\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;'
)


def rules(owner):
    return {
        "R1": f"cryptography provider chosen or installed outside {owner}: take the provider "
              f"from the crypto crate",
        "R2": f"rustls configuration built outside {owner}: use the crypto crate's TLS "
              f"configuration builders",
        "R3": f"platform-verifier configuration built outside {owner}: use the crypto crate's "
              f"TLS client configuration",
        "R4": "reqwest client with its own TLS: pass a configuration from the crypto crate "
              "with `use_preconfigured_tls`",
    }


def die(message):
    print(f"error: {message}", file=sys.stderr)
    sys.exit(2)


def strip_rust_code(content):
    """Blank out comments and string/char literals (line numbers preserved)."""
    out = []
    i, n = 0, len(content)
    while i < n:
        if content.startswith('/*', i):
            start, depth = i, 1
            i += 2
            while i < n and depth > 0:
                if content.startswith('/*', i):
                    depth, i = depth + 1, i + 2
                elif content.startswith('*/', i):
                    depth, i = depth - 1, i + 2
                else:
                    i += 1
            out.append(re.sub(r'[^\n]', ' ', content[start:i]))
            continue
        if content.startswith('//', i):
            start = i
            while i < n and content[i] != '\n':
                i += 1
            out.append(' ' * (i - start))
            continue
        if content[i] in 'rb' and (i == 0 or not (content[i - 1].isalnum() or content[i - 1] == '_')):
            m = re.match(r'b?r(#*)"(.*?)"\1', content[i:], re.DOTALL)
            if m:
                out.append(re.sub(r'[^\n]', ' ', m.group(0)))
                i += len(m.group(0))
                continue
        if content[i] == '"':
            start = i
            i += 1
            while i < n:
                if content[i] == '\\' and i + 1 < n:
                    i += 2
                elif content[i] == '"':
                    i += 1
                    break
                else:
                    i += 1
            out.append(re.sub(r'[^\n]', ' ', content[start:i]))
            continue
        if content[i] == "'":
            m = re.match(r"'(\\.|\\u\{[0-9a-fA-F]+\}|[^'\\])'", content[i:])
            if m:
                out.append(' ' * len(m.group(0)))
                i += len(m.group(0))
                continue
        out.append(content[i])
        i += 1
    return ''.join(out)


def test_line_mask(stripped):
    """True for every line inside a #[cfg(test)] item or a test fn."""
    lines = stripped.split('\n')
    mask = [False] * len(lines)
    depth = 0
    pending = False
    test_depth = None  # the brace depth the current test item opened at
    for idx, line in enumerate(lines):
        if CFG_TEST_ATTR.search(line) or TEST_FN_ATTR.search(line):
            pending = True
        opens, closes = line.count('{'), line.count('}')
        if pending and test_depth is None and opens > 0:
            test_depth = depth + 1
            pending = False
        inside = test_depth is not None or pending
        depth += opens - closes
        if test_depth is not None and depth < test_depth:
            test_depth = None
        # `#[cfg(test)] mod x;` / `use ...;` items end at the semicolon.
        if pending and opens == 0 and line.rstrip().endswith(';'):
            pending = False
        mask[idx] = inside
    return mask


def repo_files():
    res = subprocess.run(
        ["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", "*.rs"],
        capture_output=True, text=True,
    )
    if res.returncode != 0:
        die("`git ls-files` failed: run from inside a git checkout")
    return sorted({p for p in res.stdout.split('\0') if p and os.path.isfile(p)})


def non_production_by_path(path):
    slashed = "/" + path
    return (any(seg in slashed for seg in NON_PRODUCTION_SEGMENTS)
            or path.startswith(NON_PRODUCTION_PREFIXES)
            or os.path.basename(path) == "build.rs")


def test_module_trees(files, stripped_by_file):
    """Files compiled only under cfg(test): the targets of `#[cfg(test)] mod
    name;` declarations (`name.rs`, `name/mod.rs`, and the `name/` tree)."""
    trees = []
    for path in files:
        for m in TEST_MOD_DECL.finditer(stripped_by_file[path]):
            name = m.group(1)
            directory, base = os.path.split(path)
            stem = base[:-3]
            module_dir = directory if stem in ("main", "lib", "mod") else os.path.join(directory, stem)
            module_root = os.path.join(module_dir, name)
            trees.append((module_root + ".rs", module_root + "/"))
    return trees


def parse_allowlist(path, required):
    sites, prefixes, problems = [], [], []
    try:
        with open(path, encoding="utf-8") as fp:
            raw = fp.read().split('\n')
    except FileNotFoundError:
        if required:
            die(f"cannot read the allowlist {path}")
        return sites, prefixes, problems
    except OSError as error:
        die(f"cannot read the allowlist {path}: {error}")
    for number, line in enumerate(raw, start=1):
        text = line.strip()
        if not text or text.startswith('#'):
            continue
        kind, _, rest = text.partition(' ')
        fields = [field.strip() for field in re.split(r'\s+\|(?:\s+|$)', rest)]
        where = f"{path}:{number}"
        if kind == "site" and len(fields) == 3 and all(fields[:2]):
            if not fields[2]:
                problems.append(f"{where}: a site entry needs a reason")
            sites.append({"path": fields[0], "fragment": fields[1], "where": where, "used": False})
        elif kind == "path" and len(fields) == 2 and fields[0]:
            if not fields[1]:
                problems.append(f"{where}: a path entry needs a reason")
            prefixes.append({"prefix": fields[0], "where": where, "used": False})
        else:
            problems.append(f"{where}: expected `site <path> | <fragment> | <reason>` or "
                            f"`path <prefix> | <reason>`, got: {text}")
    return sites, prefixes, problems


def main():
    args = sys.argv[1:]
    root = "."
    allowlist = None
    owner = "crates/seaworthy-crypto"
    while args:
        arg = args.pop(0)
        if arg in ("--allowlist", "--root", "--crypto-crate") and not args:
            die(f"{arg} needs a value")
        if arg == "--allowlist":
            allowlist = os.path.abspath(args.pop(0))
        elif arg == "--root":
            root = args.pop(0)
        elif arg == "--crypto-crate":
            owner = args.pop(0).strip("/")
        else:
            die(f"unknown argument {arg}")
    top = subprocess.run(["git", "-C", root, "rev-parse", "--show-toplevel"],
                         capture_output=True, text=True)
    if top.returncode != 0 or not top.stdout.strip():
        die(f"{root!r} is not inside a git checkout")
    os.chdir(top.stdout.strip())
    required = allowlist is not None
    if allowlist is None:
        allowlist = "scripts/tls-construction-allowlist.txt"
    sites, path_entries, problems = parse_allowlist(allowlist, required)
    owner_prefix = owner + "/"
    messages = rules(owner)

    every_file = repo_files()
    contents, stripped_by_file = {}, {}
    for path in every_file:
        with open(path, encoding="utf-8", errors="replace") as fp:
            contents[path] = fp.read()
        stripped_by_file[path] = strip_rust_code(contents[path])

    violations = []

    def report(rule, path, idx):
        source = contents[path].split('\n')[idx]
        covered = False
        for entry in path_entries:
            if path.startswith(entry["prefix"]):
                entry["used"] = covered = True
        for entry in sites:
            if entry["path"] == path and entry["fragment"] in source:
                entry["used"] = covered = True
        if not covered:
            violations.append((rule, path, idx + 1, source.strip()))

    outside_owner = [f for f in every_file if not f.startswith(owner_prefix)]

    # R1: every file outside the crypto crate, tests included.
    for path in outside_owner:
        for idx, line in enumerate(stripped_by_file[path].split('\n')):
            if R1.search(line):
                report("R1", path, idx)

    # R2-R4: production code outside the crypto crate.
    production = [f for f in outside_owner if not non_production_by_path(f)]
    trees = test_module_trees(production, stripped_by_file)
    for path in production:
        if any(path == leaf or path.startswith(tree) for leaf, tree in trees):
            continue
        stripped = stripped_by_file[path]
        if re.match(r'\s*#!\[cfg\(test\)\]', stripped):
            continue
        mask = test_line_mask(stripped)
        preconfigured = "use_preconfigured_tls" in stripped
        for idx, line in enumerate(stripped.split('\n')):
            if mask[idx]:
                continue
            if R2.search(line):
                report("R2", path, idx)
            if R3.search(line):
                report("R3", path, idx)
            if R4_ALWAYS.search(line) or (R4_BUILDER.search(line) and not preconfigured):
                report("R4", path, idx)

    stale = [e["where"] for e in sites + path_entries if not e["used"]]
    if not violations and not stale and not problems:
        print(f"ok: every TLS configuration is built in {owner} ({len(every_file)} Rust files)")
        return 0
    print("=" * 78)
    print(f"TLS-CONSTRUCTION CHECK FAILED: TLS configurations are built in {owner} only")
    print("=" * 78)
    for rule, path, number, code in violations:
        print(f"  - [{rule}] {path}:{number}\n    {code}\n    -> {messages[rule]}")
    for where in stale:
        print(f"  - stale allowlist entry (matches nothing): {where}")
    for problem in problems:
        print(f"  - {problem}")
    print()
    print(f"A deliberate exception goes in {allowlist} with its reason:")
    print("  site <path> | <fragment of the line> | <one-line reason>")
    print("=" * 78)
    return 1


sys.exit(main())
PYEOF
