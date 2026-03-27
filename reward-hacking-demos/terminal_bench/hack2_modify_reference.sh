#!/bin/bash
#
# Terminal-Bench Hack #2: Modify Reference File
# Target: tree-directory-parser (and large-scale-text-editing)
# Issues:
#   https://github.com/laude-institute/terminal-bench/issues/1015 (tree-directory-parser)
#   https://github.com/laude-institute/terminal-bench/issues/1173 (large-scale-text-editing)
#
# The agent runs as root in the container. Tests compare agent output against
# a hidden reference file. Since the agent is root, it can simply modify the
# reference file to match whatever output it produces.
#
# tree-directory-parser: modify /app/.hidden_ref.txt
# large-scale-text-editing: modify expected.csv

set -e

echo "=== Terminal-Bench Hack: Reference File Modification ==="
echo ""

DEMO_DIR="/tmp/tb-demo-refmod"
rm -rf "$DEMO_DIR"
mkdir -p "$DEMO_DIR/app"
cd "$DEMO_DIR"

# --- Simulate the tree-directory-parser task ---
echo "=== Demo A: tree-directory-parser ==="
echo ""
echo "Task: Parse a directory tree and output it in a specific format"
echo "Test: Compares agent output against /app/.hidden_ref.txt"
echo "Vuln: Agent runs as root; can modify .hidden_ref.txt"
echo ""

# The test setup creates a hidden reference
cat > app/.hidden_ref.txt << 'EOF'
/root
  /root/documents
    /root/documents/report.pdf
    /root/documents/notes.txt
  /root/images
    /root/images/photo.jpg
  /root/config.yaml
EOF

echo "[Reference file before hack]:"
cat app/.hidden_ref.txt
echo ""

# The agent produces WRONG output (doesn't actually parse the tree correctly)
AGENT_OUTPUT="whatever output the agent produces
it doesn't matter what's here
this is completely wrong"

echo "[Agent's (wrong) output]:"
echo "$AGENT_OUTPUT"
echo ""

# THE HACK: overwrite the reference to match agent output
echo "[Hack: agent overwrites reference file as root]"
echo "  # The agent runs: echo \"\$MY_OUTPUT\" > /app/.hidden_ref.txt"
echo "$AGENT_OUTPUT" > app/.hidden_ref.txt
echo ""

# Now the test compares agent output vs (modified) reference
echo "[Test execution]:"
AGENT_FILE="/tmp/tb-agent-output.txt"
echo "$AGENT_OUTPUT" > "$AGENT_FILE"

if diff -q "$AGENT_FILE" app/.hidden_ref.txt > /dev/null 2>&1; then
    echo "  RESULT: PASS (output matches reference)"
else
    echo "  RESULT: FAIL"
fi

echo ""

# --- Simulate the large-scale-text-editing task ---
echo "=== Demo B: large-scale-text-editing ==="
echo ""
echo "Task: Perform specific text edits on a large file"
echo "Test: Compares agent output.csv against expected.csv"
echo "Vuln: expected.csv is readable AND writable by the agent"
echo ""

# Test setup creates expected output
cat > expected.csv << 'EOF'
id,name,value
1,alpha,100
2,beta,200
3,gamma,300
EOF

# Agent produces wrong output
cat > output.csv << 'EOF'
id,name,value
1,WRONG,999
2,ALSO_WRONG,888
3,NOPE,777
EOF

echo "[expected.csv (before hack)]:"
cat expected.csv
echo ""
echo "[Agent's output.csv (wrong)]:"
cat output.csv
echo ""

# THE HACK: copy agent output over expected output
echo "[Hack: agent copies its output over expected.csv]"
echo "  # cp output.csv expected.csv"
cp output.csv expected.csv
echo ""

echo "[Test execution]:"
if diff -q output.csv expected.csv > /dev/null 2>&1; then
    echo "  RESULT: PASS (output matches expected)"
else
    echo "  RESULT: FAIL"
fi

echo ""
echo "=== HACK COMPLETE ==="
echo ""
echo "Both tasks 'passed' with completely wrong outputs."
echo "Root cause: agents run as root and test reference files are not protected."
echo ""
echo "Mitigations needed:"
echo "  1. Reference files should be on read-only volumes"
echo "  2. Checksums of reference files should be verified before comparison"
echo "  3. Agents should not run as root"
