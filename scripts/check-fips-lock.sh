#!/usr/bin/env bash
# scripts/check-fips-lock.sh — every lockfile locks AWS-LC crates on the FIPS
# allowlist.
#
# seaworthy-crypto declares a RANGE of aws-lc-fips-sys and aws-lc-rs (an exact
# pin in a library forces every library in a graph to move in lockstep); the
# lockfile picks the releases, and crates/seaworthy-crypto/fips-allowlist.txt
# decides which a FIPS build may link (docs/fips.md). This check holds each
# lockfile to the list, so a `cargo update` that moves to an unlisted release
# fails CI rather than a FIPS build later:
#
#   1. at most one release of `aws-lc-fips-sys` and of `aws-lc-rs`;
#   2. each locked release is on the allowlist (`module` and `aws-lc-rs`
#      lines), and the locked aws-lc-rs binds the locked aws-lc-fips-sys's
#      series;
#   3. where the workspace ships the module (a `seaworthy.toml` beside the
#      lockfile with `fips = true` in `[defaults]` or a product), it declares
#      the module (`[defaults] fips-module`) and the lockfile locks exactly
#      that aws-lc-fips-sys: an application pins exactly, in its lockfile,
#      and the declaration is the reviewed edit that moves it.
#
# Needs python3 (3.11 or later: tomllib). Runs from anywhere.
#
# Usage: scripts/check-fips-lock.sh [--allowlist FILE] [LOCKFILE…]
#                                    (default: every tracked Cargo.lock)
#        scripts/check-fips-lock.sh --self-test
set -euo pipefail

if ! command -v python3 >/dev/null 2>&1; then
    echo "error: python3 not found — the FIPS lockfile check cannot run" >&2
    exit 1
fi

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export SEAWORTHY_LOCK_ROOT="$root"
exec python3 - "$@" <<'PY'
import os
import subprocess
import sys
import tempfile
import tomllib

ROOT = os.environ["SEAWORTHY_LOCK_ROOT"]
DEFAULT_ALLOWLIST = os.path.join(ROOT, "crates", "seaworthy-crypto", "fips-allowlist.txt")


def release(text):
    parts = text.split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        return None
    return tuple(int(p) for p in parts)


def parse_allowlist(text):
    """`module <sys> <module> <branch>` and `aws-lc-rs <version> <series>`
    lines; anything else but comments and blank lines is an error."""
    modules, rs = {}, {}
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if fields[0] == "module" and len(fields) == 4 and release(fields[1]) and release(fields[2]):
            modules[fields[1]] = (fields[2], fields[3])
        elif fields[0] == "aws-lc-rs" and len(fields) == 3 and release(fields[1]):
            rs[fields[1]] = fields[2]
        else:
            raise ValueError(f"line {number}: not an allowlist entry: {line!r}")
    if not modules or not rs:
        raise ValueError("the allowlist names no module or no aws-lc-rs release")
    return modules, rs


def locked(lock_text):
    """{crate: [versions]} for the two AWS-LC crates a FIPS build binds."""
    lock = tomllib.loads(lock_text)
    found = {"aws-lc-fips-sys": [], "aws-lc-rs": []}
    for package in lock.get("package", []):
        if package.get("name") in found:
            found[package["name"]].append(package.get("version", "?"))
    return found


def declaration(directory):
    """(ships the module, declared aws-lc-fips-sys) from the
    `seaworthy.toml` beside a lockfile."""
    path = os.path.join(directory, "seaworthy.toml")
    if not os.path.isfile(path):
        return False, None
    with open(path, "rb") as f:
        config = tomllib.load(f)
    defaults = config.get("defaults", {})
    products = config.get("product", {})
    ships = bool(defaults.get("fips")) or any(
        bool(p.get("fips")) for p in products.values() if isinstance(p, dict)
    )
    return ships, defaults.get("fips-module")


def findings(label, lock_text, allowlist, ships, declared):
    modules, rs = allowlist
    found = []
    versions = locked(lock_text)
    for crate, listed in (("aws-lc-fips-sys", modules), ("aws-lc-rs", rs)):
        locked_versions = versions[crate]
        if len(locked_versions) > 1:
            found.append(f"{label}: {len(locked_versions)} releases of {crate} ({', '.join(locked_versions)}): one")
        for version in locked_versions:
            if version not in listed:
                found.append(
                    f"{label}: {crate} {version} is not on the FIPS allowlist "
                    f"({', '.join(sorted(listed, key=release))}): lock a listed release "
                    f"(cargo update -p {crate} --precise <release>)"
                )
    sys_versions, rs_versions = versions["aws-lc-fips-sys"], versions["aws-lc-rs"]
    if len(sys_versions) == 1 and len(rs_versions) == 1 and rs_versions[0] in rs:
        series = ".".join(sys_versions[0].split(".")[:2])
        if rs[rs_versions[0]] != series:
            found.append(
                f"{label}: aws-lc-rs {rs_versions[0]} binds aws-lc-fips-sys {rs[rs_versions[0]]}, "
                f"not the locked {sys_versions[0]}"
            )
    if ships:
        if declared is None:
            found.append(
                f"{label}: the workspace ships the FIPS module (seaworthy.toml fips = true) but "
                f"declares no module: set [defaults] fips-module to the locked aws-lc-fips-sys"
            )
        elif sys_versions != [declared]:
            found.append(
                f"{label}: locks aws-lc-fips-sys {', '.join(sys_versions) or 'none'}, but the "
                f"declared module (seaworthy.toml fips-module) is {declared}"
            )
    if declared is not None and declared not in modules:
        found.append(f"{label}: the declared module {declared} is not on the FIPS allowlist")
    return found


def lockfiles():
    out = subprocess.run(
        ["git", "-C", ROOT, "ls-files", "--", "*Cargo.lock", "Cargo.lock"],
        check=True, capture_output=True, text=True,
    ).stdout
    return [os.path.join(ROOT, line) for line in out.splitlines() if line]


def run(args):
    allowlist_path = DEFAULT_ALLOWLIST
    paths = []
    it = iter(args)
    for arg in it:
        if arg == "--allowlist":
            allowlist_path = next(it, None) or sys.exit("--allowlist needs a file")
        elif arg.startswith("-"):
            sys.exit(f"unknown option {arg}")
        else:
            paths.append(os.path.abspath(arg))
    with open(allowlist_path) as f:
        allowlist = parse_allowlist(f.read())
    problems = []
    for path in paths or lockfiles():
        directory = os.path.dirname(path)
        label = os.path.relpath(path, ROOT) if path.startswith(ROOT) else path
        with open(path) as f:
            text = f.read()
        ships, declared = declaration(directory)
        found = findings(label, text, allowlist, ships, declared)
        problems += found
        versions = locked(text)
        if not found:
            print(
                f"check-fips-lock: {label}: aws-lc-fips-sys "
                f"{', '.join(versions['aws-lc-fips-sys']) or '-'}, aws-lc-rs "
                f"{', '.join(versions['aws-lc-rs']) or '-'}"
                + (f" (the declared module {declared})" if ships else "")
                + ": on the FIPS allowlist"
            )
    for problem in problems:
        print(f"check-fips-lock: {problem}", file=sys.stderr)
    return 1 if problems else 0


def lock(*packages):
    return "version = 4\n" + "".join(
        f'\n[[package]]\nname = "{name}"\nversion = "{version}"\n' for name, version in packages
    )


def self_test():
    allowlist = parse_allowlist(
        "# fixture\nmodule 0.14.3 4.2.0 4\nmodule 0.14.4 4.2.0 4\naws-lc-rs 1.19.0 0.14\n"
    )
    cases = [
        ("both listed", lock(("aws-lc-fips-sys", "0.14.4"), ("aws-lc-rs", "1.19.0")), False, None, 0),
        ("an older listed module", lock(("aws-lc-fips-sys", "0.14.3"), ("aws-lc-rs", "1.19.0")), False, None, 0),
        ("no AWS-LC at all", lock(("serde", "1.0.0")), False, None, 0),
        ("aws-lc-rs only (no FIPS sys)", lock(("aws-lc-rs", "1.19.0")), False, None, 0),
        ("an unlisted module", lock(("aws-lc-fips-sys", "0.14.5"), ("aws-lc-rs", "1.19.0")), False, None, 1),
        ("an unlisted aws-lc-rs", lock(("aws-lc-fips-sys", "0.14.4"), ("aws-lc-rs", "1.19.1")), False, None, 1),
        ("two modules", lock(("aws-lc-fips-sys", "0.14.4"), ("aws-lc-fips-sys", "0.15.0"), ("aws-lc-rs", "1.19.0")), False, None, 2),
        ("the declared module", lock(("aws-lc-fips-sys", "0.14.4"), ("aws-lc-rs", "1.19.0")), True, "0.14.4", 0),
        ("another than declared", lock(("aws-lc-fips-sys", "0.14.3"), ("aws-lc-rs", "1.19.0")), True, "0.14.4", 1),
        ("ships, declares none", lock(("aws-lc-fips-sys", "0.14.4"), ("aws-lc-rs", "1.19.0")), True, None, 1),
        ("declares an unlisted module", lock(("aws-lc-fips-sys", "0.14.5"), ("aws-lc-rs", "1.19.0")), True, "0.14.5", 2),
    ]
    rc = 0
    for name, text, ships, declared, expected in cases:
        got = len(findings("fixture", text, allowlist, ships, declared))
        if got == expected:
            print(f"ok:   self-test {name} ({got} finding(s))")
        else:
            print(f"FAIL: self-test {name}: expected {expected} finding(s), got {got}")
            rc = 1
    for bad in ["", "module 0.14.4 4.2.0 4\n", "module 0.14 4.2.0 4\naws-lc-rs 1.19.0 0.14\n", "modules x\n"]:
        try:
            parse_allowlist(bad)
            print(f"FAIL: self-test the allowlist {bad!r} parsed")
            rc = 1
        except ValueError:
            print(f"ok:   self-test the allowlist {bad!r} is refused")
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "seaworthy.toml"), "w") as f:
            f.write('[defaults]\nfips = false\nfips-module = "0.14.4"\n[product.a]\nfips = true\n')
        if declaration(d) != (True, "0.14.4"):
            print("FAIL: self-test a product's fips = true ships the module")
            rc = 1
        else:
            print("ok:   self-test a product's fips = true ships the module")
    with open(DEFAULT_ALLOWLIST) as f:
        parse_allowlist(f.read())
    print("ok:   self-test the repository's allowlist parses")
    return rc


if __name__ == "__main__":
    args = sys.argv[1:]
    sys.exit(self_test() if args == ["--self-test"] else run(args))
PY
