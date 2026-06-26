# Releasing `content-addressable`

Releases are **tag-driven**. Pushing a `v*` tag runs
[`.github/workflows/release.yml`](.github/workflows/release.yml), which builds
the full multi-platform abi3 wheel matrix + an sdist and publishes them to
**PyPI via Trusted Publishing (OIDC — no stored token)** and the **core crate to
crates.io**.

> **`maturin upload` is retired.** Do not publish wheels by hand from a laptop
> with a stored PyPI token. That path produced a single Linux wheel, leaned on a
> deprecated command, and kept a long-lived secret on an interactive machine
> (issue #14). The tag-driven workflow replaces it entirely.

## One-time maintainer setup

Do this once, before the first real `v*` tag.

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
match the `publish-pypi` job in the workflow. Do not rename either without
updating this registration — OIDC will refuse the publish if they drift.

### 2. Add the crates.io token

crates.io has no OIDC trusted publishing yet, so the core crate publishes with a
token:

1. Create a scoped token at <https://crates.io/settings/tokens> (scope:
   *publish-update* for `content-addressable`).
2. Add it as the repository secret **`CARGO_REGISTRY_TOKEN`**
   (Settings → Secrets and variables → Actions).

The Python bindings crate (`content-addressable-py`) is `publish = false` and is
**never** pushed to crates.io — only the core crate is.

### 3. (Recommended) Protect the `pypi` environment

Create a GitHub environment named `pypi` (Settings → Environments) and add
required reviewers and/or a tag protection rule, so a human gate sits in front
of the irreversible PyPI publish.

## Cutting a release

1. **Bump the two version strings in lockstep.** They use different spellings
   for the same version — SemVer for Cargo, PEP 440 for the wheel — and the
   `verify` job fails the release if either disagrees with the tag:

   | File                          | Spelling | Example (rc1)   |
   | ----------------------------- | -------- | --------------- |
   | `Cargo.toml` `version`        | SemVer   | `0.1.0-rc1`     |
   | `content-addressable-py/Cargo.toml` `version` | SemVer | `0.1.0-rc1` |
   | `pyproject.toml` `version`    | PEP 440  | `0.1.0rc1`      |

   (Final releases like `0.1.0` are spelled identically in both.) Commit the
   bump on a branch, open a PR, and merge it through CI as usual.

2. **Tag and push.** From the merged commit on `main`:

   ```sh
   git tag v0.1.0-rc1
   git push origin v0.1.0-rc1
   ```

3. **The workflow does the rest:** it verifies the tag against both version
   strings, builds wheels for Linux `x86_64` + `aarch64`, macOS `universal2`,
   and Windows `x64` plus an sdist, publishes them to PyPI over OIDC, and
   publishes the core crate to crates.io. The two registry publishes are
   independent jobs — if one fails (e.g. a PyPI rate-limit), re-run that job
   from the Actions tab without redoing the other.

## Dry run (before the first real tag)

Trigger the workflow manually (**Actions → release → Run workflow**, i.e.
`workflow_dispatch`) to build the full wheel matrix + sdist, run `twine check`,
and `cargo publish --dry-run` **without publishing anything**. Use this to
validate the matrix before cutting `v0.1.0-rc1`.
