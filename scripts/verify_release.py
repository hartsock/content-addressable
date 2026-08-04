#!/usr/bin/env python3
"""Canonical release-version verification for `content-addressable`.

The single source of truth for release version agreement. Both local development
(`just verify-release`) and CI (the release gate) call THIS tool — there is no
second version-mapping implementation in YAML or shell.

It proves:

  1. The two Rust manifests declare the *same* SemVer version.
  2. The Python project version is the *canonical PEP 440 equivalent* of that
     Rust version.
  3. (When a tag is supplied) the release tag is exactly ``v<rust-version>``.

The three version declarations it reads (audited real paths — note the Python
project file is ``pyproject.toml`` at the repo ROOT, **not**
``content-addressable-py/pyproject.toml``):

  * ``Cargo.toml``                        -> ``[package].version``  (root Rust core crate)
  * ``content-addressable-py/Cargo.toml`` -> ``[package].version``  (PyO3 binding crate)
  * ``pyproject.toml``                    -> ``[project].version``  (Python distribution)

Fail-closed: missing files, unparsable/duplicate-key TOML, non-string versions,
version disagreement, unsupported/ambiguous prerelease spellings, and build
metadata all exit non-zero with a diagnostic that names the offending file and
value (never a secret).

SemVer -> PEP 440 mapping (the only supported forms):

    0.1.0          -> 0.1.0
    0.1.0-alpha.1  -> 0.1.0a1
    0.1.0-beta.2   -> 0.1.0b2
    0.1.0-rc.3     -> 0.1.0rc3
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import tomllib
from pathlib import Path

# (relative path, TOML key path to the version string)
ROOT_CARGO = ("Cargo.toml", ("package", "version"))
PY_CARGO = ("content-addressable-py/Cargo.toml", ("package", "version"))
PYPROJECT = ("pyproject.toml", ("project", "version"))

# SemVer prerelease identifier -> PEP 440 prerelease letter.
_PRERELEASE = {"alpha": "a", "beta": "b", "rc": "rc"}

_CORE_RE = re.compile(r"\d+\.\d+\.\d+")
_PRE_RE = re.compile(r"(alpha|beta|rc)\.(\d+)")


class VerifyError(Exception):
    """A release-verification failure (always names the offending input)."""


def rust_to_pep440(semver: str) -> str:
    """Map a Rust SemVer version to its canonical PEP 440 spelling, or raise.

    Supported: ``X.Y.Z``, ``X.Y.Z-alpha.N``, ``X.Y.Z-beta.N``, ``X.Y.Z-rc.N``.
    Rejected (fail closed): build metadata (``+...``) and every other prerelease
    form (``-alpha`` without a number, ``-pre``, ``-dev``, ``-alpha.beta``, ...).
    """
    if "+" in semver:
        raise VerifyError(
            f"build metadata is not supported for a release version: {semver!r}"
        )
    if "-" not in semver:
        if not _CORE_RE.fullmatch(semver):
            raise VerifyError(f"not a valid X.Y.Z release version: {semver!r}")
        return semver
    core, pre = semver.split("-", 1)
    if not _CORE_RE.fullmatch(core):
        raise VerifyError(f"not a valid X.Y.Z core in version: {semver!r}")
    m = _PRE_RE.fullmatch(pre)
    if not m:
        raise VerifyError(
            f"unsupported prerelease {pre!r} in {semver!r}; "
            "expected alpha.N, beta.N, or rc.N"
        )
    kind, num = m.group(1), m.group(2)
    if num != str(int(num)):  # reject leading zeros ("01") — ambiguous
        raise VerifyError(f"non-canonical prerelease number in {semver!r}")
    return f"{core}{_PRERELEASE[kind]}{num}"


def _read_version(root: Path, rel: str, keys: tuple[str, ...]) -> str:
    path = root / rel
    if not path.is_file():
        raise VerifyError(f"missing version file: {rel}")
    try:
        # tomllib raises TOMLDecodeError on a duplicate key, so ambiguous /
        # duplicated version declarations fail closed here.
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise VerifyError(f"unparsable TOML in {rel}: {exc}") from exc
    node: object = data
    for key in keys:
        if not isinstance(node, dict) or key not in node:
            table = ".".join(keys[:-1])
            raise VerifyError(f"no [{table}] version declared in {rel}")
        node = node[key]
    if not isinstance(node, str):
        raise VerifyError(f"version in {rel} is not a string: {node!r}")
    return node


def verify(root: Path, tag: str | None) -> list[str]:
    """Return a list of problems; an empty list means the release is consistent."""
    problems: list[str] = []
    versions: dict[str, str] = {}
    for name, (rel, keys) in {
        "root-cargo": ROOT_CARGO,
        "py-cargo": PY_CARGO,
        "pyproject": PYPROJECT,
    }.items():
        try:
            versions[name] = _read_version(root, rel, keys)
        except VerifyError as exc:
            problems.append(str(exc))
    if problems:
        return problems  # cannot compare if any declaration is unreadable

    rust = versions["root-cargo"]

    # 1. Both Rust manifests must agree exactly.
    if versions["py-cargo"] != rust:
        problems.append(
            f"Rust version disagreement: Cargo.toml={rust!r} != "
            f"content-addressable-py/Cargo.toml={versions['py-cargo']!r}"
        )

    # 2. pyproject must be the canonical PEP 440 of the Rust version.
    expected_pep440: str | None = None
    try:
        expected_pep440 = rust_to_pep440(rust)
    except VerifyError as exc:
        problems.append(f"Cargo.toml version {rust!r}: {exc}")
    if expected_pep440 is not None and versions["pyproject"] != expected_pep440:
        problems.append(
            f"pyproject.toml version {versions['pyproject']!r} is not the PEP 440 "
            f"form of Cargo.toml {rust!r} (expected {expected_pep440!r})"
        )

    # 3. Optional tag must be exactly v<rust-version>.
    if tag is not None:
        expected_tag = f"v{rust}"
        if tag != expected_tag:
            problems.append(
                f"release tag {tag!r} != expected {expected_tag!r} "
                "(must be v<Cargo.toml version>)"
            )

    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify release version agreement across the three package manifests."
    )
    parser.add_argument(
        "--tag",
        default=os.environ.get("RELEASE_TAG"),
        help="release tag to validate, e.g. v0.1.0 (or the RELEASE_TAG env var)",
    )
    parser.add_argument("--repo-root", default=Path("."), type=Path)
    args = parser.parse_args(argv)
    tag = args.tag or None

    problems = verify(args.repo_root, tag)
    if problems:
        print("release version verification FAILED:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    rust = _read_version(args.repo_root, *ROOT_CARGO)
    line = f"release version verification OK: Rust {rust!r} == PEP 440 {rust_to_pep440(rust)!r}"
    if tag is not None:
        line += f", tag {tag!r}"
    print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
