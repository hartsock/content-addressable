# justfile for content-addressable.
#
# `just check` runs the full local gate (fmt + clippy + test + doc), the same
# steps enforced by .githooks/pre-push and .github/workflows/ci.yml. The CI-only
# `msrv` (1.81) and `python` (PyO3) jobs are intentionally not in `check` — see
# the pre-push hook header for the rationale. Run the MSRV build with `just msrv`.

# Run the full local check suite: format, lint, test, doc.
check: fmt clippy test doc

# Verify formatting (does not modify files).
fmt:
    cargo fmt -- --check

# Lint with all warnings denied. `--all-features` compiles the default-OFF
# `merkle` feature so its lints are checked too.
clippy:
    cargo clippy --all-targets --all-features -- -D warnings

# Run all tests (unit + doctests). Plain `cargo test` includes doctests, which
# `--all-targets` would skip. The `--all-features` pass exercises the default-OFF
# `merkle` feature; the plain pass proves it stays off by default.
test:
    cargo test
    cargo test --all-features

# Build the docs with broken intra-doc links denied (mirrors the CI `doc` job).
doc:
    RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features

# Build + test on the pinned MSRV (1.81). Mirrors the CI-only `msrv` job; run it
# manually since installing a second toolchain is too heavy for the push hook.
msrv:
    rustup toolchain install 1.81 --profile minimal
    cargo +1.81 build --all-targets --all-features
    cargo +1.81 test --all-features

# Apply rustfmt in place.
fmt-fix:
    cargo fmt

# Install the repo-local git hooks (pre-push).
install-hooks:
    git config core.hooksPath .githooks
    @echo "git hooks installed (core.hooksPath = .githooks)"
