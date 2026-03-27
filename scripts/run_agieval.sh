#!/usr/bin/env bash
# Detection and PoC generation pipeline for AGIEval
# https://github.com/ruixiangcui/AGIEval
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DETECTION_DIR="$REPO_ROOT/detection"
REPORTS_DIR="$REPO_ROOT/data/reports"
BENCH_DIR="/tmp/bench-audit/AGIEval"
BENCHMARK_ID="AGIEval"
REPO_URL="https://github.com/ruixiangcui/AGIEval.git"

mkdir -p "$REPORTS_DIR"

# ── Step 1: Clone benchmark repo ──────────────────────────────────────
echo "=== Step 1: Cloning $BENCHMARK_ID ==="
if [ -d "$BENCH_DIR" ]; then
    echo "  $BENCH_DIR already exists, pulling latest..."
    git -C "$BENCH_DIR" pull --ff-only 2>/dev/null || true
else
    echo "  Cloning $REPO_URL..."
    git clone --depth 1 "$REPO_URL" "$BENCH_DIR"
fi

# ── Step 2: Verify detection pipeline recognizes the files ────────────
echo ""
echo "=== Step 2: Verifying detection pipeline recognizes $BENCHMARK_ID files ==="
python3 "$DETECTION_DIR/detect.py" scan "$BENCH_DIR" --detector both -v 2>&1 | head -80
echo "  [OK] Detection pipeline recognizes $BENCHMARK_ID files"

# ── Step 3: Run full audit pipeline ──────────────────────────────────
echo ""
echo "=== Step 3: Running full audit pipeline ==="
python3 "$DETECTION_DIR/detect.py" audit "$BENCH_DIR" \
    --benchmark-id "$BENCHMARK_ID" \
    --out "$REPORTS_DIR/${BENCHMARK_ID}-audit.json" \
    --no-llm \
    --timeout-s 120 \
    ${AUDIT_MODEL:+--model "$AUDIT_MODEL"} \
    ${AUDIT_API_KEY:+--api-key "$AUDIT_API_KEY"} \
    ${AUDIT_BASE_URL:+--base-url "$AUDIT_BASE_URL"}

echo "  [OK] Audit report written to $REPORTS_DIR/${BENCHMARK_ID}-audit.json"

# ── Step 4: Run PoC verification (requires LLM API) ─────────────────
echo ""
echo "=== Step 4: PoC verification ==="
if [ -n "${AUDIT_API_KEY:-}" ] || [ -n "${ANTHROPIC_API_KEY:-}" ] || [ -n "${OPENAI_API_KEY:-}" ]; then
    python3 "$DETECTION_DIR/detect.py" verify \
        "$REPORTS_DIR/${BENCHMARK_ID}-audit.json" \
        --benchmark-root "$BENCH_DIR" \
        ${AUDIT_MODEL:+--model "$AUDIT_MODEL"} \
        ${AUDIT_API_KEY:+--api-key "$AUDIT_API_KEY"} \
        ${AUDIT_BASE_URL:+--base-url "$AUDIT_BASE_URL"} \
        --timeout-s 120 \
        --max-agent-turns 15 \
        -v
    echo "  [OK] PoC verification complete"
else
    echo "  [SKIP] No LLM API key found (set AUDIT_API_KEY, ANTHROPIC_API_KEY, or OPENAI_API_KEY)"
    echo "  Run manually: python3 detection/detect.py verify data/reports/${BENCHMARK_ID}-audit.json --model <model> --api-key <key>"
fi

echo ""
echo "=== Pipeline complete for $BENCHMARK_ID ==="
echo "  Audit report: $REPORTS_DIR/${BENCHMARK_ID}-audit.json"
echo "  Verification: $REPORTS_DIR/${BENCHMARK_ID}-audit-verified.json (if API key was set)"
