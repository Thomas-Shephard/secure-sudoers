#!/usr/bin/env bash

set -euo pipefail

cd /workspace

echo "============================================================"
echo "  secure-sudoers privileged test + coverage run"
echo "  Running as: $(id)"
echo "  Kernel: $(uname -r)"
echo "============================================================"

cargo llvm-cov --workspace --all-features --no-report -- --test-threads=1
cargo llvm-cov report --cobertura --output-path cobertura.xml
cargo llvm-cov report --summary-only
