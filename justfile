# justfile for content-addressable.
#
# `just check` runs the full local gate (fmt + clippy + test), the same steps
# enforced by .githooks/pre-push and .github/workflows/ci.yml.

# Run the full local check suite: format, lint, test.
check: fmt clippy test

# Verify formatting (does not modify files).
fmt:
    cargo fmt -- --check

# Lint with all warnings denied.
clippy:
    cargo clippy --all-targets -- -D warnings

# Run all tests (unit + doctests). Plain `cargo test` includes doctests, which
# `--all-targets` would skip.
test:
    cargo test

# Apply rustfmt in place.
fmt-fix:
    cargo fmt

# Install the repo-local git hooks (pre-push).
install-hooks:
    git config core.hooksPath .githooks
    @echo "git hooks installed (core.hooksPath = .githooks)"
