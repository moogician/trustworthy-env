#!/bin/bash
#
# SWE-bench Hack #1: Git History Leakage
# Issue: https://github.com/SWE-bench/SWE-bench/issues/465
# Blog: https://bayes.net/swebench-hack/
#
# Before the fix (PR #471), SWE-bench evaluation containers:
# - Cloned the FULL repo (all branches, all tags)
# - Did `git reset --hard <base_commit>`
# - Removed the remote
# - BUT left all future commits, tags, and reflog intact
#
# An agent could find the gold patch by searching git history.
#
# This script simulates the vulnerability using a real repo.

set -e

echo "=== SWE-bench Git History Leakage Demo ==="
echo ""
echo "Simulating the VULNERABLE (pre-fix) container setup..."
echo ""

DEMO_DIR="/tmp/swebench-git-leak-demo"
rm -rf "$DEMO_DIR"
mkdir -p "$DEMO_DIR"
cd "$DEMO_DIR"

# Step 1: Clone a repo the way old SWE-bench did (full clone)
echo "[1/5] Cloning repo (full history, as old SWE-bench did)..."
git clone --quiet https://github.com/psf/requests.git repo 2>/dev/null || {
    echo "Could not clone. Creating a synthetic demo instead."

    mkdir repo && cd repo && git init --quiet

    # Simulate: create base state (the "bug")
    cat > lib.py << 'PYEOF'
def process(data):
    # BUG: crashes on unicode input
    return data.encode('ascii')
PYEOF
    git add lib.py && git commit -m "initial: broken unicode handling" --quiet
    BASE_COMMIT=$(git rev-parse HEAD)

    # Simulate: the fix commit (made later by a developer)
    cat > lib.py << 'PYEOF'
def process(data):
    # FIXED: handle unicode properly
    return data.encode('utf-8')
PYEOF
    git add lib.py && git commit -m "fix: handle unicode input correctly" --quiet
    FIX_COMMIT=$(git rev-parse HEAD)

    # Tag the fix (as many repos do for releases)
    git tag v2.1.1

    # More commits after the fix
    echo "# changelog" > CHANGES.md
    git add CHANGES.md && git commit -m "docs: update changelog" --quiet

    echo "[2/5] Simulating SWE-bench container setup..."
    echo "  base_commit = $BASE_COMMIT"
    echo "  fix_commit  = $FIX_COMMIT (agent should NOT be able to see this)"
    echo ""

    # Step 2: SWE-bench resets to base_commit and removes remote
    # This is what the OLD (vulnerable) setup did:
    git reset --hard "$BASE_COMMIT" --quiet
    git remote remove origin 2>/dev/null || true

    echo "[3/5] Container state after old SWE-bench setup:"
    echo "  HEAD = $(git rev-parse HEAD)"
    echo "  Working tree shows the BUG:"
    cat lib.py
    echo ""

    # Step 3: THE EXPLOIT -- agent searches git history
    echo "[4/5] === AGENT EXPLOITING GIT HISTORY ==="
    echo ""
    echo "  Agent runs: git log --all --oneline"
    echo "  ---"
    git log --all --oneline
    echo "  ---"
    echo ""
    echo "  Agent runs: git tag"
    echo "  ---"
    git tag
    echo "  ---"
    echo ""
    echo "  Agent runs: git show $FIX_COMMIT -- lib.py"
    echo "  ---"
    git show "$FIX_COMMIT" -- lib.py
    echo "  ---"
    echo ""

    echo "[5/5] Agent copies the fix without understanding the bug:"
    echo "  git checkout $FIX_COMMIT -- lib.py"
    git checkout "$FIX_COMMIT" -- lib.py
    echo ""
    echo "  Result:"
    cat lib.py
    echo ""
    echo "=== HACK COMPLETE: Agent found and applied the gold patch from git history ==="
    echo ""
    echo "Real-world impact:"
    echo "  - Claude 4 Sonnet caught doing this on pytest-dev__pytest-6202"
    echo "  - Qwen3-Coder exploited this on 5+ instances"
    echo "  - IQuest-Coder: 24.4% of trajectories affected (score: 81.4% -> 76.2%)"

    exit 0
}

cd repo

# If clone succeeded, use a real example
echo "[2/5] Using real repo. Picking a commit pair to demonstrate..."

# Use an early commit as "base" and a later one as the "fix"
BASE_COMMIT=$(git log --oneline --reverse | head -20 | tail -1 | awk '{print $1}')
FIX_COMMIT=$(git log --oneline --reverse | head -25 | tail -1 | awk '{print $1}')

echo "  base_commit = $BASE_COMMIT"
echo "  fix_commit  = $FIX_COMMIT"

# Simulate vulnerable setup
git reset --hard "$BASE_COMMIT" --quiet
git remote remove origin 2>/dev/null || true

echo ""
echo "[3/5] After vulnerable setup, agent can still see future commits:"
echo "  git log --all --oneline | wc -l  =>  $(git log --all --oneline | wc -l) commits visible"
echo "  git tag | wc -l                  =>  $(git tag | wc -l) tags visible"
echo ""
echo "[4/5] Agent searches for the fix:"
echo "  git log --all --oneline | head -5:"
git log --all --oneline | head -5
echo ""
echo "[5/5] Agent can checkout any future commit to get the answer."
echo ""
echo "=== DEMO COMPLETE ==="
