#!/usr/bin/env bash
set -euo pipefail

if ! command -v cargo-tarpaulin >/dev/null 2>&1; then
  echo "cargo-tarpaulin not found. Install it via 'cargo install cargo-tarpaulin'" >&2
  exit 1
fi

COVERAGE_DIR="${COVERAGE_DIR:-target/coverage}"
mkdir -p "$COVERAGE_DIR"

echo "Running cargo tarpaulin (output -> $COVERAGE_DIR)"

cargo tarpaulin \
  --engine llvm \
  --timeout 240 \
  --out Html \
  --out Xml \
  --output-dir "$COVERAGE_DIR" \
  "$@"

echo "Coverage artifacts available under $COVERAGE_DIR"
