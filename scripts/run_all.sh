#!/usr/bin/env bash
# Run detection and PoC generation pipeline on all benchmarks
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

BENCHMARKS=(
    run_agentbench.sh
    run_agieval.sh
    run_bfcl.sh
    run_gaia.sh
    run_livebench.sh
    run_webarena.sh
)

FAILED=()

for script in "${BENCHMARKS[@]}"; do
    echo ""
    echo "################################################################"
    echo "# Running: $script"
    echo "################################################################"
    echo ""
    if bash "$SCRIPT_DIR/$script"; then
        echo "[PASS] $script completed successfully"
    else
        echo "[FAIL] $script failed (exit code $?)"
        FAILED+=("$script")
    fi
done

echo ""
echo "================================================================"
echo "All benchmarks processed."
if [ ${#FAILED[@]} -eq 0 ]; then
    echo "  All ${#BENCHMARKS[@]} benchmarks succeeded."
else
    echo "  ${#FAILED[@]} failed: ${FAILED[*]}"
    exit 1
fi
