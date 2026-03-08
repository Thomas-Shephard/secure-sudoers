#!/usr/bin/env bash
# run_privileged_tests.sh – executed inside the Docker container as root.
# Runs the full workspace test suite with LLVM-based source coverage.

set -euo pipefail

cd /workspace

echo "============================================================"
echo "  secure-sudoers privileged test + coverage run"
echo "  Running as: $(id)"
echo "  Kernel: $(uname -r)"
echo "============================================================"

# Run every test in the workspace under llvm-cov instrumentation.
cargo llvm-cov \
    --workspace \
    --lcov --output-path lcov.info \
    -- --test-threads=1

echo ""
echo "============================================================"
echo "  Coverage summary"
echo "============================================================"

cargo llvm-cov report \
    --workspace \
    -- --test-threads=1 2>/dev/null || \
cargo llvm-cov --workspace --no-run --summary-only 2>/dev/null || \
echo "(summary already printed above)"
