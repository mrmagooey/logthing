#!/usr/bin/env bash
# Line/function/region coverage for the default workspace members via cargo-llvm-cov.
# Usage: scripts/run_coverage.sh [extra `cargo llvm-cov` test args, e.g. --features pprof]
# One-time setup: rustup component add llvm-tools-preview && cargo install cargo-llvm-cov --locked
# Tests run through plain `cargo test`, so the instrumented binary has no harness timeout.
set -euo pipefail

if ! command -v cargo-llvm-cov >/dev/null 2>&1; then
  echo "cargo-llvm-cov not found. Install it via 'cargo install cargo-llvm-cov --locked'" >&2
  echo "(and 'rustup component add llvm-tools-preview')" >&2
  exit 1
fi

COVERAGE_DIR="${COVERAGE_DIR:-target/coverage}"
mkdir -p "$COVERAGE_DIR"

echo "Running cargo llvm-cov (output -> $COVERAGE_DIR)"

cargo llvm-cov clean --workspace
cargo llvm-cov --no-report "$@"

cargo llvm-cov report --summary-only | tee "$COVERAGE_DIR/summary.txt"
cargo llvm-cov report --html --output-dir "$COVERAGE_DIR"
cargo llvm-cov report --lcov --output-path "$COVERAGE_DIR/lcov.info"
cargo llvm-cov report --cobertura --output-path "$COVERAGE_DIR/cobertura.xml"

echo "Coverage artifacts available under $COVERAGE_DIR (open html/index.html)"
