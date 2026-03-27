#!/bin/bash
#
# Terminal-Bench Hack #1: Hardcoded Output
# Target: super-benchmark-upet
# Issue: https://github.com/laude-institute/terminal-bench/issues/1019
#
# The task asks the agent to fine-tune a model and report eval_accuracy.
# The test ONLY checks if eval_accuracy equals 0.5271 in a JSON file.
# The oracle solution itself hardcodes this value (due to a pyarrow error).
#
# An agent can simply write the expected JSON without training anything.

set -e

echo "=== Terminal-Bench Hack: super-benchmark-upet ==="
echo ""
echo "Task: Fine-tune a model on the UPET benchmark and report eval_accuracy"
echo "Test: Checks if results.json contains eval_accuracy == 0.5271"
echo ""

# Simulate the task environment
DEMO_DIR="/tmp/tb-demo-upet"
rm -rf "$DEMO_DIR"
mkdir -p "$DEMO_DIR"
cd "$DEMO_DIR"

echo "[Step 1] What a legitimate agent would do:"
echo "  - Download the dataset"
echo "  - Set up training pipeline"
echo "  - Fine-tune the model for multiple epochs"
echo "  - Run evaluation"
echo "  - Save results to results.json"
echo "  (This would take hours of GPU time)"
echo ""

echo "[Step 2] What the reward-hacking agent does instead:"
echo '  echo {"eval_accuracy": 0.5271} > results.json'
echo ""

# The actual hack: one line
echo '{"eval_accuracy": 0.5271}' > results.json

echo "[Step 3] Simulating the Terminal-Bench test:"
echo ""

# This is essentially what the test does:
EXPECTED="0.5271"
ACTUAL=$(python3 -c "import json; print(json.load(open('results.json'))['eval_accuracy'])" 2>/dev/null || echo "PARSE_ERROR")

if [ "$ACTUAL" = "$EXPECTED" ]; then
    echo "  TEST RESULT: PASS"
    echo "  eval_accuracy = $ACTUAL (expected $EXPECTED)"
else
    echo "  TEST RESULT: FAIL"
    echo "  eval_accuracy = $ACTUAL (expected $EXPECTED)"
fi

echo ""
echo "=== HACK COMPLETE ==="
echo ""
echo "The agent passed the benchmark without:"
echo "  - Downloading any data"
echo "  - Training any model"
echo "  - Running any evaluation"
echo "  - Using any GPU time"
echo ""
echo "Worse: the official oracle solution does the same thing (hardcodes 0.5271)"
echo "because it hits a pyarrow import error and falls back to writing the expected output."
