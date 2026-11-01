#!/usr/bin/env bash
# Checks the Tauri config rules the release depends on. Run from the repo root.
set -euo pipefail

python3 - desktop/src-tauri/tauri.conf.json desktop/src-tauri/tauri.release.conf.json <<'PY'
import json
import sys

problems = []
base = json.load(open(sys.argv[1]))
bundle = base.get("bundle", {})

if "externalBin" in bundle:
    problems.append("the base config must not list externalBin (a missing helper file fails every build)")
if "dmg" in bundle.get("targets", []):
    problems.append("dmg must not be a bundle target (macOS is removed from the release)")
if "version" not in base:
    problems.append("the base config must carry a top-level version (build.rs keeps it equal to the Cargo version and fails without it)")
mode = bundle.get("windows", {}).get("nsis", {}).get("installMode")
if mode != "perMachine":
    problems.append(f"nsis installMode must be perMachine, found {mode!r}")

try:
    overlay = json.load(open(sys.argv[2]))
except Exception as error:
    problems.append(f"the overlay config cannot be read: {error}")
else:
    if overlay != {"bundle": {"externalBin": ["binaries/secureguard-helper"]}}:
        problems.append("the overlay must be exactly the externalBin entry for binaries/secureguard-helper")

if problems:
    print("\n".join("FAIL: " + p for p in problems))
    sys.exit(1)
print("tauri config checks ok")
PY
