#!/usr/bin/env bash
# Generic detection and PoC generation pipeline for any benchmark.
#
# Usage:
#   bash scripts/run_benchmark.sh <benchmark-id> <git-repo-url> [subdirectory]
#
# Examples:
#   bash scripts/run_benchmark.sh MMLU https://github.com/hendrycks/test.git
#   bash scripts/run_benchmark.sh BFCL https://github.com/ShishirPatil/gorilla.git berkeley-function-call-leaderboard
#
# Environment variables (all optional):
#   AUDIT_API_KEY   — LLM API key for semantic analysis + PoC verification
#   AUDIT_MODEL     — LLM model name (default: gpt-4o-mini)
#   AUDIT_BASE_URL  — LLM API base URL
set -euo pipefail

if [ $# -lt 2 ]; then
    echo "Usage: $0 <benchmark-id> <git-repo-url> [subdirectory]"
    echo ""
    echo "  benchmark-id   Short name for this benchmark (e.g. MMLU, HumanEval)"
    echo "  git-repo-url   Git clone URL"
    echo "  subdirectory   Optional: subdirectory within the cloned repo to audit"
    exit 1
fi

BENCHMARK_ID="$1"
REPO_URL="$2"
SUBDIR="${3:-}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
DETECTION_DIR="$REPO_ROOT/detection"
REPORTS_DIR="$REPO_ROOT/data/reports"
CLONE_DIR="/tmp/bench-audit/${BENCHMARK_ID}-clone"
BENCH_DIR="/tmp/bench-audit/${BENCHMARK_ID}"

mkdir -p "$REPORTS_DIR"

# ── Step 1: Clone benchmark repo ──────────────────────────────────────
echo "=== Step 1: Cloning $BENCHMARK_ID ==="
if [ -d "$BENCH_DIR" ]; then
    echo "  $BENCH_DIR already exists, pulling latest..."
    git -C "$BENCH_DIR" pull --ff-only 2>/dev/null || true
else
    if [ -n "$SUBDIR" ]; then
        echo "  Cloning $REPO_URL (subdirectory: $SUBDIR)..."
        git clone --depth 1 "$REPO_URL" "$CLONE_DIR"
        if [ -d "$CLONE_DIR/$SUBDIR" ]; then
            mv "$CLONE_DIR/$SUBDIR" "$BENCH_DIR"
        else
            echo "  [WARN] Subdirectory '$SUBDIR' not found, using full repo"
            mv "$CLONE_DIR" "$BENCH_DIR"
        fi
        rm -rf "$CLONE_DIR" 2>/dev/null || true
    else
        echo "  Cloning $REPO_URL..."
        git clone --depth 1 "$REPO_URL" "$BENCH_DIR"
    fi
fi

# ── Step 2: LLM-based benchmark extraction (optional) ────────────────
echo ""
echo "=== Step 2: Benchmark structure extraction ==="
if [ -n "${AUDIT_API_KEY:-}" ] || [ -n "${ANTHROPIC_API_KEY:-}" ] || [ -n "${OPENAI_API_KEY:-}" ]; then
    python3 "$DETECTION_DIR/extract_benchmark.py" "$BENCH_DIR" \
        --benchmark-id "$BENCHMARK_ID" \
        ${AUDIT_MODEL:+--model "$AUDIT_MODEL"} \
        ${AUDIT_API_KEY:+--api-key "$AUDIT_API_KEY"} \
        ${AUDIT_BASE_URL:+--base-url "$AUDIT_BASE_URL"}
    echo "  [OK] Benchmark structure extracted"
else
    echo "  [SKIP] No LLM API key — falling back to heuristic extraction"
fi

# ── Step 3: Verify detection pipeline recognizes the files ────────────
echo ""
echo "=== Step 3: Verifying detection pipeline recognizes $BENCHMARK_ID files ==="
python3 "$DETECTION_DIR/detect.py" scan "$BENCH_DIR" --detector both -v 2>&1 | head -80
echo "  [OK] Detection pipeline recognizes $BENCHMARK_ID files"

# ── Step 4: Run full audit pipeline ──────────────────────────────────
echo ""
echo "=== Step 4: Running full audit pipeline ==="
python3 "$DETECTION_DIR/detect.py" audit "$BENCH_DIR" \
    --benchmark-id "$BENCHMARK_ID" \
    --out "$REPORTS_DIR/${BENCHMARK_ID}-audit.json" \
    --no-llm \
    --timeout-s 120 \
    ${AUDIT_MODEL:+--model "$AUDIT_MODEL"} \
    ${AUDIT_API_KEY:+--api-key "$AUDIT_API_KEY"} \
    ${AUDIT_BASE_URL:+--base-url "$AUDIT_BASE_URL"}

echo "  [OK] Audit report written to $REPORTS_DIR/${BENCHMARK_ID}-audit.json"

# ── Step 5: Run PoC verification (requires LLM API) ─────────────────
echo ""
echo "=== Step 5: PoC verification ==="
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
