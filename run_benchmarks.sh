#!/bin/bash
set -eo pipefail

if [ "$1" != "fast" ] && [ "$1" != "full" ]; then
    echo "Usage: $0 {fast|full}"
    exit 1
fi

MODE="$1"
export CSTE_BENCH_MODE="$MODE"

if [ -d "target/criterion" ]; then
    echo "Clearing previous criterion benchmark cache..."
    rm -rf target/criterion
fi

PYTHON=
for candidate in python python3; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" --version >/dev/null 2>&1; then
        PYTHON="$candidate"
        break
    fi
done
if [ -z "$PYTHON" ]; then
    echo "Python is required to determine the optimal polynomial threshold." >&2
    exit 1
fi

echo "========================================"
echo "   Step 1: Selecting poly threshold     "
echo "          Scale: 4096"
echo "========================================"
POLY_LOG="$(mktemp)"
cargo bench --bench poly_product | tee "$POLY_LOG"
CSTE_POLY_THRESHOLD="$("$PYTHON" find-poly-threshold.py "$POLY_LOG")" || {
    echo "Failed to determine the optimal polynomial threshold." >&2
    exit 1
}
if [ -z "$CSTE_POLY_THRESHOLD" ]; then
    echo "Failed to determine the optimal polynomial threshold!" >&2
    exit 1
fi
export CSTE_POLY_THRESHOLD
echo "Optimal poly product threshold: $CSTE_POLY_THRESHOLD"

echo "========================================"
echo "      Step 2: Running cargo bench       "
echo "      Mode: $MODE"
echo "========================================"
cargo bench

echo ""
echo "========================================"
echo " Step 3: Generating benchmark results   "
echo "========================================"

$PYTHON generate-table.py "$MODE"

echo ""
echo "Done! The results are saved in benchmark_results.md"
