#!/usr/bin/env bash

set -euo pipefail

cd /workspace

echo "============================================================"
echo "  secure-sudoers privileged test + coverage run"
echo "  Running as: $(id)"
echo "  Kernel: $(uname -r)"
echo "============================================================"

echo "Building binaries for full-path E2E tests..."
cargo build --workspace --all-features --bins

echo "Running Bats full user journey tests..."
bats -t /workspace/tests/e2e_full_user_path.bats

CARGO_INCREMENTAL=0 cargo llvm-cov --workspace --all-features --no-report -- --test-threads=1
cargo llvm-cov report --cobertura --output-path cobertura.xml
cargo llvm-cov report --summary-only
