# Releasing `content-addressable`

Releases are **tag-driven**. Pushing a `v*` tag runs
[`.github/workflows/release.yml`](.github/workflows/release.yml), which — only
after a common pre-publish gate passes — builds the full multi-platform abi3
wheel matrix + an sdist and publishes them to **PyPI via Trusted Publishing
(OIDC — no stored token)** and the **core crate to crates.io**.

> **`maturin upload` is retired.** Do not publish wheels by hand from a laptop
> with a stored PyPI token. That path produced a single Linux wheel, leaned on a
> deprecated command, and kept a long-lived secret on an interactive machine
> (issue #14). The tag-driven workflow replaces it entirely.

## The gate (what must be green before anything publishes)

Every job below must succeed before **either** registry publish starts. The two
publishes `need:` a single `release-gate` aggregator, which itself needs the
whole DAG — so a hostile or accidental route to publishing untested or
mismatched artifacts does not exist:

```
provenance ─┐
rust-gate ──┼─► build-wheels ─► install-smoke ─┐
msrv ───────┘   build-sdist ──► sdist-smoke  ──┼─► release-gate ─► publish-pypi
                                                │                  publish-crate
                                                └─ (all of the above)
```

| Job            | What it proves |
| -------------- | -------------- |
| `provenance`   | The three version declarations agree, the tag is exactly `v<Cargo.toml version>`, `HEAD` **is** the tag's commit, and that commit is contained in `main` (`git merge-base --is-ancestor`). A tag on an out-of-band commit is rejected. |
| `rust-gate`    | `just check` + `just verify-release` + `cargo fmt --check`, `clippy -D warnings --all-features`, `cargo test --locked` (default **and** `--all-features`), rustdoc `-D warnings`, and **`cargo publish --dry-run`**. |
| `msrv`         | Builds + tests on the pinned MSRV `1.85` so a transitive dep cannot silently raise the floor. |
| `build-wheels` / `build-sdist` | Build the **distributable** artifacts (abi3 wheels per platform + sdist) and `twine check` them. |
| `install-smoke` / `sdist-smoke` | Install the **built** wheel/sdist into a clean venv across py3.9/3.12/3.13 × Linux/macOS/Windows, import from `site-packages`, and run the golden-vector + fail-closed profile-validation + README tests against the *installed* package — never the source tree. |
| `release-gate` | Aggregator; the two publishes depend only on this. |

The publishes never rebuild: they download the exact artifacts the gate already
validated and hand them to PyPI / crates.io.

## Version strings — there are **three**, in two spellings

The SemVer core (`Cargo.toml`) is the source of truth. The Python distribution
version is its canonical PEP 440 equivalent. All three must agree, and
`scripts/verify_release.py` (invoked by `just verify-release` and the
`provenance` job) is the **single** implementation of the mapping — there is no
second copy in YAML or shell.

| File                                          | Spelling | Example (rc) |
| --------------------------------------------- | -------- | ------------ |
| `Cargo.toml` `[package].version`              | SemVer   | `0.1.0-rc.1` |
| `content-addressable-py/Cargo.toml` `[package].version` | SemVer | `0.1.0-rc.1` |
| `pyproject.toml` `[project].version`          | PEP 440  | `0.1.0rc1`   |

### SemVer → PEP 440 (the only supported forms)

| Cargo.toml (SemVer) | pyproject.toml (PEP 440) |
| ------------------- | ------------------------ |
| `0.1.0`             | `0.1.0`                  |
| `0.1.0-alpha.1`     | `0.1.0a1`                |
| `0.1.0-beta.2`      | `0.1.0b2`                |
| `0.1.0-rc.3`        | `0.1.0rc3`               |

**The prerelease number needs a dot in SemVer** (`-rc.1`, not `-rc1`) and **no
dot in PEP 440** (`rc1`). Build metadata (`+…`) and every other prerelease
spelling (`-pre`, `-dev`, `-alpha` without a number, leading zeros) are rejected
fail-closed. The tag is always `v` + the exact `Cargo.toml` SemVer string
(`v0.1.0-rc.1`).

## Cutting a release

1. **Bump the three version strings in lockstep** (SemVer in the two
   `Cargo.toml` files, PEP 440 in `pyproject.toml`). Keep this on its **own**
   commit/PR — do not fold a version bump into unrelated work. Open a PR and
   merge it through CI as usual.

2. **Verify locally before tagging.** The same check the `provenance` job runs:

   ```sh
   just verify-release                # drift guard: the three versions agree
   just verify-release v0.1.0-rc.1    # release guard: also assert tag == v<version>
   ```

   A dry-run of the whole pipeline (build the matrix, `twine check`,
   `cargo publish --dry-run`, **publishing nothing**) is available from
   **Actions → release → Run workflow** (`workflow_dispatch`).

3. **Tag and push** from the merged commit on `main` (the `provenance` job
   rejects a tag whose commit is not contained in `main`):

   ```sh
   git tag v0.1.0-rc.1
   git push origin v0.1.0-rc.1
   ```

4. **The workflow does the rest:** runs the full gate above, then publishes the
   wheels + sdist to PyPI over OIDC and the core crate to crates.io.

### If a publish partially fails

The two registry publishes are independent jobs that both gate on
`release-gate`. If one succeeds and the other fails (e.g. a PyPI rate-limit or a
transient crates.io error), **re-run only the failed job** from the Actions tab.
The publishes consume the already-built, already-validated artifacts, so a
re-run cannot produce different bytes than the ones the gate approved. Never
re-tag or hand-publish to "fix" a partial outage — that is how mismatched
artifacts reach a registry.

## Classifiers & maturity

`pyproject.toml` declares `Development Status :: 3 - Alpha`, matching the current
alpha version. Advance this **deliberately**: move to `4 - Beta` / `5 -
Production/Stable` only when the frozen `0.1.x` contract has shipped and there is
real evidence for the claim. Do not label the package Production/Stable to make a
release "look finished".

## One-time maintainer setup

Do this once, before the first real `v*` tag. **None of it can be verified by
CI** — the workflow assumes it is in place. See the checklist at the end.

### 1. Register the PyPI Trusted Publisher (no token)

On PyPI: **Account settings → Publishing → Add a pending publisher**, for the
project `content-addressable`, with **exactly** these values:

| Field             | Value                  |
| ----------------- | ---------------------- |
| PyPI Project Name | `content-addressable`  |
| Owner             | `hartsock`             |
| Repository name   | `content-addressable`  |
| Workflow name     | `release.yml`          |
| Environment name  | `pypi`                 |

The **workflow filename (`release.yml`)** and the **environment (`pypi`)** must
match the `publish-pypi` job. Do not rename either without updating this
registration — OIDC will refuse the publish if they drift.

### 2. Add the crates.io token

crates.io has no OIDC trusted publishing yet, so the core crate publishes with a
token:

1. Create a scoped token at <https://crates.io/settings/tokens> (scope:
   *publish-update* for `content-addressable`).
2. Add it as the repository secret **`CARGO_REGISTRY_TOKEN`**
   (Settings → Secrets and variables → Actions).

The Python bindings crate (`content-addressable-py`) is `publish = false` and is
**never** pushed to crates.io — only the core crate is.

### 3. Create the deployment environments

Create **two** GitHub environments (Settings → Environments) so a human gate
sits in front of each irreversible publish:

- **`pypi`** — used by `publish-pypi` (must match the Trusted Publisher above).
- **`crates-io`** — used by `publish-crate`; scope the `CARGO_REGISTRY_TOKEN`
  secret to it.

Add required reviewers and/or a tag protection rule (`v*`) to each so the
publish waits on an explicit human approval.

### 4. Protect `main` and the `v*` tags

The `provenance` job asserts the release commit is contained in `main`, but that
guarantee is only as strong as branch/tag protection:

- Branch protection on `main` (require the PR + CI checks; no direct pushes).
- Tag protection for `v*` so only maintainers can create release tags.

## Human-only configuration checklist

CI cannot see or assert any of these. Confirm all before the first real tag:

- [ ] PyPI **pending publisher** registered with the exact values above.
- [ ] `CARGO_REGISTRY_TOKEN` secret present, scoped to `content-addressable`.
- [ ] `pypi` **and** `crates-io` environments exist, with required reviewers.
- [ ] `main` branch protection on; `v*` tag protection on.
- [ ] The three version strings agree (`just verify-release`) and the intended
      tag matches (`just verify-release v<version>`).
