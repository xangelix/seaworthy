#!/usr/bin/env bash
# Describe the workspace for CI, as `key=value` lines for $GITHUB_OUTPUT.
#
#   scripts/ci/plan.sh                  # print the plan
#   scripts/ci/plan.sh >>"$GITHUB_OUTPUT"
#
# The workflows run over whatever `crates/*` holds (the workspace is
# `members = ["crates/*"]`), so they work with no crates at all and keep
# working as crates land. Cargo refuses most commands on a workspace with no
# members; the jobs that need one are skipped until `crates=true`.
#
#   crates        true when crates/ holds at least one package
#   features      every feature of every member EXCEPT the FIPS ones, as a
#                 comma-separated `package/feature` list for `cargo --features`
#                 (empty when there are none). A feature is FIPS when its name
#                 or anything it enables mentions "fips": the FIPS module is a
#                 separate, slow C build with its own job.
#   fips          true when a member declares a `fips` feature
#   cli           true when crates/seaworthy is the `seaworthy` package
#   version       workspace.package.version
#   msrv          workspace.package.rust-version as a full x.y.z version
#   fuzz-targets  JSON array of the fuzz targets (fuzz/Cargo.toml [[bin]] names)
#
# Edition 2024 has no implicit features for optional dependencies, so each
# manifest's [features] table is the complete list. Names are checked against
# a conservative charset (they reach shell commands through `env:`).
#
# Needs python3 >= 3.11 (tomllib); exit 2 when the workspace can't be read.
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

exec python3 -I - <<'PY'
import glob
import json
import os
import re
import sys
import tomllib

NAME = re.compile(r"^[A-Za-z0-9_-]+$")
FEATURE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_+.-]*$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$")
MSRV = re.compile(r"^[0-9]+\.[0-9]+(\.[0-9]+)?$")


def die(message):
    print(f"plan: {message}", file=sys.stderr)
    sys.exit(2)


def load(path):
    try:
        with open(path, "rb") as fp:
            return tomllib.load(fp)
    except (OSError, tomllib.TOMLDecodeError) as error:
        die(f"cannot read {path}: {error}")


root = load("Cargo.toml")
workspace_package = root.get("workspace", {}).get("package", {})

version = workspace_package.get("version", "")
if not VERSION.match(version):
    die(f"workspace.package.version {version!r} is not a version")
msrv = workspace_package.get("rust-version", "")
if not MSRV.match(msrv):
    die(f"workspace.package.rust-version {msrv!r} is not a Rust version")
if msrv.count(".") == 1:
    msrv += ".0"

packages = []
for manifest in sorted(glob.glob("crates/*/Cargo.toml")):
    data = load(manifest)
    package = data.get("package")
    if not package:
        continue
    name = package.get("name", "")
    if not NAME.match(name):
        die(f"{manifest}: package name {name!r} is outside [A-Za-z0-9_-]")
    features = data.get("features", {})
    for feature in features:
        if not FEATURE.match(feature):
            die(f"{manifest}: feature {feature!r} is outside [A-Za-z0-9_+.-]")
    packages.append((manifest, name, features))

selected = []
fips = False
cli = False
for manifest, name, features in packages:
    if name == "seaworthy" and manifest == "crates/seaworthy/Cargo.toml":
        cli = True
    for feature, enables in sorted(features.items()):
        if feature == "fips":
            fips = True
        if feature == "default":
            continue
        if "fips" in feature or any("fips" in str(entry) for entry in enables):
            continue
        selected.append(f"{name}/{feature}")

fuzz_targets = []
fuzz = load("fuzz/Cargo.toml") if os.path.exists("fuzz/Cargo.toml") else {}
for entry in fuzz.get("bin", []):
    target = entry.get("name", "")
    if not re.match(r"^[a-z0-9_]+$", target):
        die(f"fuzz/Cargo.toml: target name {target!r} is outside [a-z0-9_]")
    fuzz_targets.append(target)

print(f"crates={'true' if packages else 'false'}")
print(f"features={','.join(selected)}")
print(f"fips={'true' if fips else 'false'}")
print(f"cli={'true' if cli else 'false'}")
print(f"version={version}")
print(f"msrv={msrv}")
print(f"fuzz-targets={json.dumps(sorted(fuzz_targets), separators=(',', ':'))}")
PY
