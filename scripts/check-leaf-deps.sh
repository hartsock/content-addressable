#!/usr/bin/env bash
# check-leaf-deps.sh — the LEAF invariant guard (issue #13).
#
# The published core crate `content-addressable` is the bottom of the stack:
# kyln, agent-store, agent-mesh, and newt all depend on it to share ONE
# byte/wire contract for `ContentId`. That only holds if the published core
# stays a true LEAF — its resolved dependency closure must contain ZERO path,
# git, or other non-crates.io-registry edges. The moment the core gains a
# path/git dependency, every downstream repo either fails to build from
# crates.io or pulls in an un-publishable cycle, and a path/git dep can also
# silently swap the canonicalization/hashing impl under `from_canonical_bytes`
# without a crates.io version bump — a byte-contract concern, not just packaging.
#
# This guard resolves `cargo metadata` and walks the dependency closure rooted
# at the `content-addressable` package ONLY, asserting every reachable package's
# `source` is the crates.io registry. It deliberately scopes to the published
# core: the workspace's one legitimate non-registry edge —
# `content-addressable-py -> content-addressable { path = ".." }` (that member
# is `publish = false` and outside `default-members`) — is a REVERSE dependency
# of the core, so it is never inside the core's forward closure and never trips
# this guard.
#
# It reads only `cargo metadata` (no build, no committed Cargo.lock required —
# cargo resolves from the manifests at run time), so it is fast and offline.
#
# PIPELINE PARITY: this is the `leaf-deps` job in
# .github/workflows/ci.yml and the `just leaf` recipe. It also runs in
# .githooks/pre-push (true parity — `cargo metadata` is cheap and offline).
# When editing this file, keep those three call sites in sync.
set -euo pipefail

# The published core package name. Its closure must be registry-only.
CORE_PKG="content-addressable"

# `cargo metadata` gives us, per package, a `source` field (null => local
# path/git workspace member; "registry+...crates.io-index" => crates.io) and a
# `resolve` graph we can walk to compute the core's forward closure. Stash the
# JSON in a temp file (so the python heredoc owns stdin, and cargo's progress
# diagnostics on stderr can never pollute the JSON stream the parser reads).
metadata_file="$(mktemp)"
trap 'rm -f "$metadata_file"' EXIT
cargo metadata --format-version 1 >"$metadata_file"

CORE_PKG="$CORE_PKG" METADATA_FILE="$metadata_file" python3 - <<'PY'
import json
import os
import sys

core_name = os.environ["CORE_PKG"]
with open(os.environ["METADATA_FILE"], encoding="utf-8") as fh:
    md = json.load(fh)

packages = {p["id"]: p for p in md["packages"]}
resolve = md.get("resolve")
if resolve is None:
    sys.exit("leaf guard: `cargo metadata` returned no resolve graph (cannot "
             "compute the dependency closure).")
nodes = {n["id"]: n for n in resolve["nodes"]}

# Locate the published core package by name. There is exactly one.
core_ids = [pid for pid, p in packages.items() if p["name"] == core_name]
if len(core_ids) != 1:
    sys.exit(f"leaf guard: expected exactly one '{core_name}' package, "
             f"found {len(core_ids)}: {core_ids}")
core_id = core_ids[0]

# Walk the FORWARD dependency closure rooted at the core package. The py
# member's `path` edge points AT the core (a reverse dep), so it is never
# reached here — the guard tolerates it implicitly by construction.
seen = set()
stack = [core_id]
while stack:
    cur = stack.pop()
    if cur in seen:
        continue
    seen.add(cur)
    for dep in nodes[cur]["deps"]:
        stack.append(dep["pkg"])

REGISTRY_PREFIX = "registry+"
offenders = []
for pid in seen:
    if pid == core_id:
        # The root crate itself is a local path (it IS this repo); that is
        # expected and not a dependency edge.
        continue
    pkg = packages[pid]
    source = pkg.get("source")
    if source is None or not source.startswith(REGISTRY_PREFIX):
        offenders.append((pkg["name"], pkg.get("version", "?"),
                          source if source is not None else "path/local"))

if offenders:
    print(f"LEAF GUARD FAILED: the published core '{core_name}' has "
          f"non-registry dependencies in its closure:", file=sys.stderr)
    for name, version, source in sorted(offenders):
        print(f"  - {name} {version}  (source: {source})", file=sys.stderr)
    print("\nThe published core MUST be a true leaf: every dependency in its "
          "closure must come from the crates.io registry (no path/git/"
          "workspace edges), so any repo can depend on it without cycles and "
          "the byte contract can't be swapped without a crates.io version bump.",
          file=sys.stderr)
    sys.exit(1)

count = len(seen) - 1  # exclude the core root itself
print(f"leaf guard OK: '{core_name}' closure is registry-only "
      f"({count} dependencies, all from crates.io).")
PY
