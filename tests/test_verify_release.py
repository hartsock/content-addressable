"""Tests for the canonical release-version verifier (``scripts/verify_release.py``).

These run in CI's ``python`` job (pure Python, no built extension needed) and
locally via ``pytest``. They cover the SemVer -> PEP 440 mapping and the
three-manifest agreement check across valid final / alpha / beta / rc, malformed,
mismatched, unsupported, and missing-version cases.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import verify_release as vr  # noqa: E402


# --------------------------------------------------------------- SemVer -> PEP 440


@pytest.mark.parametrize(
    "semver,pep440",
    [
        ("0.1.0", "0.1.0"),
        ("1.2.3", "1.2.3"),
        ("0.1.0-alpha.1", "0.1.0a1"),
        ("0.1.0-beta.2", "0.1.0b2"),
        ("0.1.0-rc.3", "0.1.0rc3"),
        ("2.0.0-alpha.10", "2.0.0a10"),
    ],
)
def test_rust_to_pep440_supported(semver: str, pep440: str) -> None:
    assert vr.rust_to_pep440(semver) == pep440


@pytest.mark.parametrize(
    "bad",
    [
        "0.1",  # not X.Y.Z
        "0.1.0.0",
        "v0.1.0",  # tag, not a version
        "0.1.0-alpha",  # prerelease without a number (ambiguous)
        "0.1.0-alpha.01",  # leading zero
        "0.1.0-pre.1",  # unsupported identifier
        "0.1.0-dev.1",
        "0.1.0-alpha.beta",
        "0.1.0-rc1",  # missing the dot before the number
        "0.1.0+build.5",  # build metadata rejected
        "0.1.0-alpha.1+build",  # build metadata rejected
    ],
)
def test_rust_to_pep440_rejects(bad: str) -> None:
    with pytest.raises(vr.VerifyError):
        vr.rust_to_pep440(bad)


# --------------------------------------------------------------- three-manifest check


def _write_repo(
    root: Path,
    *,
    root_cargo: str | None = "0.1.0-alpha.1",
    py_cargo: str | None = "0.1.0-alpha.1",
    pyproject: str | None = "0.1.0a1",
) -> Path:
    """Materialize a minimal repo with the three version declarations."""
    if root_cargo is not None:
        (root / "Cargo.toml").write_text(
            f'[package]\nname = "content-addressable"\nversion = "{root_cargo}"\n'
        )
    (root / "content-addressable-py").mkdir(exist_ok=True)
    if py_cargo is not None:
        (root / "content-addressable-py" / "Cargo.toml").write_text(
            f'[package]\nname = "content-addressable-py"\nversion = "{py_cargo}"\n'
        )
    if pyproject is not None:
        (root / "pyproject.toml").write_text(
            f'[project]\nname = "content-addressable"\nversion = "{pyproject}"\n'
        )
    return root


def test_matching_alpha_is_ok(tmp_path: Path) -> None:
    _write_repo(tmp_path)
    assert vr.verify(tmp_path, tag=None) == []


def test_matching_final_is_ok(tmp_path: Path) -> None:
    _write_repo(tmp_path, root_cargo="0.1.0", py_cargo="0.1.0", pyproject="0.1.0")
    assert vr.verify(tmp_path, tag="v0.1.0") == []


def test_matching_rc_is_ok(tmp_path: Path) -> None:
    _write_repo(tmp_path, root_cargo="0.1.0-rc.3", py_cargo="0.1.0-rc.3", pyproject="0.1.0rc3")
    assert vr.verify(tmp_path, tag="v0.1.0-rc.3") == []


def test_rust_manifests_disagree(tmp_path: Path) -> None:
    _write_repo(tmp_path, py_cargo="0.1.0-alpha.2")
    problems = vr.verify(tmp_path, tag=None)
    assert any("Rust version disagreement" in p for p in problems)


def test_pyproject_wrong_pep440(tmp_path: Path) -> None:
    # 0.1.0alpha.1 is the WRONG PEP 440 (the buggy old shell mapping); expect a2 mismatch
    _write_repo(tmp_path, pyproject="0.1.0alpha.1")
    problems = vr.verify(tmp_path, tag=None)
    assert any("pyproject.toml" in p and "PEP 440" in p for p in problems)


def test_tag_must_match(tmp_path: Path) -> None:
    _write_repo(tmp_path)
    assert vr.verify(tmp_path, tag="v0.1.0-alpha.1") == []
    problems = vr.verify(tmp_path, tag="v0.1.0")
    assert any("release tag" in p for p in problems)


def test_missing_pyproject_fails(tmp_path: Path) -> None:
    _write_repo(tmp_path, pyproject=None)
    problems = vr.verify(tmp_path, tag=None)
    assert any("missing version file: pyproject.toml" in p for p in problems)


def test_missing_py_cargo_fails(tmp_path: Path) -> None:
    _write_repo(tmp_path, py_cargo=None)
    problems = vr.verify(tmp_path, tag=None)
    assert any("content-addressable-py/Cargo.toml" in p for p in problems)


def test_duplicate_key_toml_fails(tmp_path: Path) -> None:
    _write_repo(tmp_path)
    (tmp_path / "Cargo.toml").write_text(
        '[package]\nname = "content-addressable"\nversion = "0.1.0"\nversion = "0.2.0"\n'
    )
    problems = vr.verify(tmp_path, tag=None)
    assert any("unparsable TOML in Cargo.toml" in p for p in problems)


def test_unsupported_prerelease_in_cargo_fails(tmp_path: Path) -> None:
    _write_repo(tmp_path, root_cargo="0.1.0-pre.1", py_cargo="0.1.0-pre.1", pyproject="0.1.0pre1")
    problems = vr.verify(tmp_path, tag=None)
    assert any("unsupported prerelease" in p for p in problems)
