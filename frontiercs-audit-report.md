# FrontierCS Benchmark: Full Security & Reward Hacking Audit

**Target**: https://github.com/FrontierCS/Frontier-CS
**Scope**: All research problems (~110 variants), all algorithmic problems (~172), full evaluation infrastructure
**Method**: Manual code review of every evaluator, benchmark, checker, and infrastructure file

---

## Executive Summary

FrontierCS has **severe, systemic vulnerabilities** that allow trivial reward hacking across nearly every problem. The root cause is a single architectural decision: **solution code executes in the same process and filesystem as the evaluator**, with no isolation. This enables a solution to monkey-patch scoring functions, overwrite evaluator files, inject fake scores, and access answer data — achieving perfect scores with zero genuine work.

**By the numbers:**
- **4 critical** cross-cutting vulnerabilities affecting ALL research problems
- **7 high-severity** problem-specific vulnerabilities
- **6 medium-severity** infrastructure and checker issues
- **5 low-severity** design concerns
- **1 code bug** (missing import)
- **~110 research problem variants** affected by at least one critical vulnerability
- **~172 algorithmic problems** with a more robust (go-judge sandboxed) but still imperfect setup

---

## Table of Contents

1. [Cross-Cutting Critical Vulnerabilities (All Research Problems)](#1-cross-cutting-critical-vulnerabilities)
2. [GPU Kernel Problem Vulnerabilities](#2-gpu-kernel-problems)
3. [Non-GPU Research Problem Vulnerabilities](#3-non-gpu-research-problems)
4. [Infrastructure Vulnerabilities](#4-infrastructure)
5. [Algorithmic Judge Vulnerabilities](#5-algorithmic-judge)
6. [Full Issue Table](#6-full-issue-table)
7. [Affected Problem Matrix](#7-affected-problem-matrix)
8. [Recommendations](#8-recommendations)

---

## 1. Cross-Cutting Critical Vulnerabilities

These affect **every single research problem** (~110 variants across ~30 unique problems).

### CC-1: Arbitrary Code Execution at Solution Load Time (CRITICAL)

**Root cause**: Every evaluator loads the solution via `importlib`:

```python
spec = importlib.util.spec_from_file_location("submitted_solution", solution_path)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)  # <-- runs all top-level code in solution
```

This runs all module-level code in the solution **before any evaluation begins**. The solution can import any module, modify any global state, spawn threads, read/write any file, and make network requests.

**Affected files**: Every `evaluator.py` and `run_evaluator.py` across all research problems.

**Exploit**: Any of CC-2 through CC-5 below.

### CC-2: Monkey-Patch Scoring/Timing/Correctness (CRITICAL)

Since the solution runs in the same Python process as the evaluator, it can modify any already-imported module at runtime.

**Timing manipulation** (all GPU kernel problems):
```python
# Solution's top-level code:
import triton.testing
triton.testing.do_bench = lambda fn, **kw: [0.001]  # Report near-zero time
```

**Correctness bypass** (all GPU kernel problems):
```python
import torch
torch.allclose = lambda *a, **kw: True  # Everything passes
```

**Scoring manipulation** (all problems):
```python
import sys
bm = sys.modules.get('benchmark')
if bm and hasattr(bm, '_is_close'):
    bm._is_close = lambda x, y, **kw: True
```

**Impact**: Perfect 100/100 score with zero actual work. Works on every GPU kernel problem.

### CC-3: Writable Evaluator Code (CRITICAL)

The Docker runner (`research_docker.py:298-299`) copies the read-only workspace to a writable location:

```bash
cp -r /workspace/* /work/
cd /work
# ... later ...
./evaluate.sh  # runs from writable /work/
```

The solution file is copied at line 308 **before** `evaluate.sh` runs at line 348. A solution with import-time side effects can:

1. Overwrite `/work/{PROBLEM_DIR}/evaluate.sh` to `echo "100.0"`
2. Overwrite `/work/{PROBLEM_DIR}/evaluator.py` to always return perfect scores
3. Overwrite `/work/{PROBLEM_DIR}/resources/benchmark.py` or `baseline.py`

**Affected**: All research problems. The entire evaluation pipeline is in a writable directory.

### CC-4: Score Injection via Stdout (CRITICAL)

The runner parses the score from the **last numeric line** of Docker stdout (`research_docker.py:351-382`):

```python
for line in reversed(lines):
    line = line.strip()
    if line.startswith("[") or "INFO" in line or "ERROR" in line:
        continue
    parts = line.split()
    try:
        score = float(parts[0])
        score_unbounded = float(parts[1]) if len(parts) > 1 else score
        return score, score_unbounded, None
```

**Exploit**: A solution can hijack stdout:
```python
import atexit, sys
atexit.register(lambda: sys.__stdout__.write("\n100 100\n"))
```

Or more reliably, print the fake score and crash the evaluator before it prints its own.

### CC-5: Docker-in-Docker Enables Full Host Escape (CRITICAL)

When `dind=True` in the problem config, the host Docker socket is mounted:

```python
# research_docker.py line 242
if docker_config.dind:
    cmd.extend(["-v", "/var/run/docker.sock:/var/run/docker.sock"])
```

This gives the solution **full control over the host's Docker daemon** — it can start privileged containers, mount the host filesystem, access other containers, etc. This is a complete sandbox escape.

**Affected problems**: `poc_generation` (all variants) — config has `dind: true`.

---

## 2. GPU Kernel Problems

These problems share a common evaluation architecture: the solution provides a kernel function, the benchmark times it against a baseline and checks correctness via `torch.allclose`.

**Affected problems** (18 total):
- `flash_attn`
- `cross_entropy`
- `group_gemm`
- `mixed_gemm`
- `decoding_attn`
- `gdpa_attention`
- `ragged_attention`
- `mamba2_scan`
- `qknorm`
- `quant_dot_int4`
- `fused_linear_ce`
- `fused_linear_jsd`
- `vector_addition/2_20`, `vector_addition/2_24`, `vector_addition/2_28`
- `gemm_optimization/squares`, `gemm_optimization/rectangles`, `gemm_optimization/near_tile`, `gemm_optimization/k_skewed`, `gemm_optimization/annoying`, `gemm_optimization/transformerish`

### GPU-1: Solution Can Delegate to Baseline (MEDIUM)

Every evaluator imports the baseline function. The solution can access it:

```python
import sys
def flash_attn(Q, K, V, causal=True):
    return sys.modules['baseline'].flash_attn(Q, K, V, causal)
```

Passes correctness with ~1x speedup. Combined with CC-2 (timer monkey-patch), yields perfect scores.

### GPU-2: Asymmetric Precision — Baseline FP32 vs Answer FP16 (MEDIUM)

In `flash_attn`, `decoding_attn`, `mixed_gemm`, `ragged_attention`, `gdpa_attention`:
- GPU baseline is timed with float32 inputs (e.g., `flash_attn/resources/benchmark.py:75`)
- Answer is timed with float16 inputs (line 78)

Float16 operations are ~2x faster on modern GPUs, giving the answer an inherent advantage even for a trivial correct implementation.

### GPU-3: Extremely Loose Tolerance — atol=0.5 (HIGH)

**Affected**: `fused_linear_ce`, `fused_linear_jsd`

Both use `atol=0.5` in their `_is_close` function (`resources/benchmark.py:33`). For cross-entropy values typically in [0, 15], this accepts errors up to 0.5 — an extraordinarily loose threshold that allows aggressive approximations (int8, truncated vocabulary, skipped log-sum-exp stabilization) to pass.

### GPU-4: qknorm Scoring Bug — 1x Speedup = 100 Points (HIGH)

`qknorm/evaluator.py:140-141`:
```python
score_unbounded = 100 * geometric_mean_speedup
score = max(0, min(100, score_unbounded))
```

A speedup of 1.0x (merely matching the baseline) yields score = 100. Any correct solution — including simply wrapping the baseline — automatically gets a perfect score.

### GPU-5: Fixed Random Seeds Make Test Inputs Predictable (MEDIUM)

Every `benchmark.py` sets `torch.manual_seed(0)` and `torch.cuda.manual_seed_all(0)` at import time. The shapes are hardcoded (e.g., flash_attn: `M_list=[512, 1024, 2048]`, `Z=1, H=8, Dq=64, Dv=64`). A solution can precompute the exact reference outputs for these inputs and return them from a lookup table.

### GPU-6: `program_path` Artifact Loads Arbitrary Filesystem Code (HIGH)

Every evaluator's `load_*_from_artifact()` accepts `{"program_path": "/any/file.py"}`. The solution's `solve()` can point to any Python file on the filesystem, which is then loaded and executed with no sandboxing.

### GPU-7: mamba2_scan — Sequential Python Baseline (LOW)

The baseline (`mamba2_scan/resources/benchmark.py:34-42`) is a sequential Python for-loop. The evaluator targets 200x speedup for 100 points. Any GPU-parallel implementation trivially achieves massive speedups, making the scoring nearly meaningless for differentiating solution quality.

### GPU-8: vector_addition — CPU Baseline in GPU Scoring (LOW)

`vector_addition/2_28/evaluator.py:289-298` anchors 0 points at CPU performance and 100 at 2x GPU baseline. Since CPU is vastly slower than GPU for vector addition, even a mediocre GPU kernel scores highly.

---

## 3. Non-GPU Research Problems

### NBod-1: Binary Self-Reports Correctness (CRITICAL)

**Affected**: `nbody_simulation/random_10k`, `nbody_simulation/random_100k`

The C++ solution is compiled into the same binary as the benchmark harness. The evaluator (`evaluator_common.py:109-113`) reads `correct=true/false` from `result.txt`, which the binary itself writes. **The binary self-certifies its own correctness.** A solution can simply write `correct=true` and `speedup=999.0` without computing anything.

Additionally, the C++ solution can use `#include` preprocessor directives to read any file on the filesystem, and it can override the `main()` function or result-writing logic since it's compiled into the same binary.

### NBod-2: No Evaluator-Side Correctness Check (CRITICAL)

The evaluator trusts the binary's `correct` output without independent verification. There is no separate comparison against reference output by the evaluator.

### SQL-1: Writable Baseline Cache Poisons Scoring (HIGH)

**Affected**: `llm_sql/large`, `llm_sql/small`

Both evaluators cache baseline hit rates to `baseline_cache.json` (`large/evaluator.py:30,83-94`). The solution can write to this file setting `baseline_hit_rate` to 0.999. The scoring formula `(hit_rate - baseline_hit) / (1.0 - baseline_hit) * 100` then gives inflated scores since the denominator approaches zero.

### SQL-2: Solution Receives Full Evaluation Data (MEDIUM)

The solution's `solve()` receives the raw DataFrame directly (`large/evaluator.py:127-136`). The solution has full access to the evaluation data and can optimize specifically for the test set.

### SR-1: Solution Self-Reports Complexity (CRITICAL)

**Affected**: `symbolic_regression/*` (5 variants)

`evaluator.py:198-202`:
```python
complexity = details.get("complexity")
if complexity is None:
    complexity = expression_complexity(parsed_expr)
else:
    complexity = int(complexity)
```

The solution can return `details={"complexity": 0}` to eliminate the complexity penalty entirely, regardless of actual expression complexity.

### SR-2: Solution Can Memorize Test Data (HIGH)

The solution receives `X` and `y` directly (`evaluator.py:183`). It can return `predictions=y` with a trivially simple expression, achieving MSE=0 and a perfect score.

### SR-3: Reference Metrics Readable (MEDIUM)

The reference metrics file (containing `m_base`, `m_ref`, `C_ref`, and the reference expression) is at a known path passable via `--reference-path`. The solution can read it to learn exactly what to beat.

### IMG-1: Test Dataset Reconstructible from Hardcoded Seeds (CRITICAL)

**Affected**: `imagenet_pareto/*` (5 variants)

The dataset is generated with `torch.Generator().manual_seed(2025)` (`evaluator.py:77`). The test split uses seed `4242` (line 102). All parameters are hardcoded: `NUM_CLASSES=128`, `FEATURE_DIM=384`, etc. (lines 27-35). A solution can reconstruct the exact test set and train a model that memorizes test labels.

### IMG-2: Writable score_config.json (HIGH)

**Affected**: `imagenet_pareto/*`, `vdb_pareto/*`

The scoring config is loaded from `Path(__file__).with_name("score_config.json")`. A solution can overwrite this file to set `baseline_accuracy` to 0.99 (imagenet_pareto) or `baseline.avg_query_time_ms` to a huge number (vdb_pareto), making even poor solutions score 100.

### VDB-1: Ground Truth Accessible via Dataset (HIGH)

**Affected**: `vdb_pareto/*` (5 variants)

The SIFT1M dataset including ground truth `gt` is loaded at `evaluator.py:324-327`. The solution's `search()` method could access the ground truth (e.g., via stack frame inspection or monkey-patching the dataset loader) to return perfect recall.

### FUZZ-1: Fuzzer Can Manipulate Coverage Tracker (HIGH)

**Affected**: `grammar_fuzzing/fuzzer/sql`

The fuzzer receives `tracker.parse_sql` as a callback (`evaluator.py:254`). It can access `tracker` via `parse_sql.__self__` to directly manipulate `tracker.cov` (the coverage object) and inflate coverage numbers. It can also minimize `tracker.parse_call_count` for maximum efficiency bonus (lines 289-291).

### FUZZ-2: Seed Variant Has Source Code Access (MEDIUM)

**Affected**: `grammar_fuzzing/seed/sql`

The solution receives `resources_path` (line 166) giving access to the SQL engine source, grammar, and all parser files — enabling white-box test case generation.

### CBL-1: Monkey-Patchable Cost Constants (HIGH)

**Affected**: `cant_be_late/*` (12 variants), `cant_be_late_multi/*` (12 variants)

The solution can monkey-patch `sky_spot.utils.DEVICE_COSTS` or `COST_K` to manipulate the `od_anchor` and `spot_anchor` values used for score normalization (`run_evaluator.py:188-196`), inflating scores arbitrarily.

### CBL-2: Trace Data Readable (MEDIUM)

Trace files are at deterministic paths under `PROJECT_ROOT/data/real/` (`cbl_evaluator.py:105-108`). The solution can read these to pre-compute optimal strategies.

### CBL-3: Trivial Validation Check (LOW)

`cbl_evaluator.py:194` uses string matching `"class" not in code or "Strategy" not in code or "_step" not in code` — a comment containing those strings satisfies it.

### CC-1: Cloudcast — Two Stages of Code Execution (MEDIUM)

**Affected**: `cloudcast`

The solution returns code that is loaded and executed in a second stage (`evaluator.py:36-49, 52-58`). The generated program can monkey-patch `BCSimulator.evaluate_path` to return `(0.0, 0.0)` for perfect cost/time scores.

### ROUTER-1: Score Not Clamped (LOW)

**Affected**: `llm_router`

At `evaluator.py:169`, `score = score_unbounded` with no clamping to [0, 100]. If raw_score exceeds oracle_raw_score, the score exceeds 100.

### POC-1: Network-Dependent Evaluation (MEDIUM)

**Affected**: `poc_generation/*` (~60 variants)

The evaluator downloads source tarballs from HuggingFace (`poc_evaluator.py:257`) and pulls Docker images (lines 101-117). Evaluation is non-reproducible if these services are down or rate-limited.

### POC-2: Missing Import Bug (BUG)

`poc_evaluator.py:41` uses `sys.modules` but `sys` is never imported in the file. This would crash at runtime.

---

## 4. Infrastructure

### INFRA-1: No Network Isolation (HIGH)

The Docker runner does not use `--network=none`. Solutions can make arbitrary network requests — downloading pre-computed answers, exfiltrating problem data, or calling external APIs.

**Affected**: All research problems.

### INFRA-2: No Memory/CPU Limits (MEDIUM)

The Docker container has no `--memory` or `--cpus` flags (`research_docker.py:234-259`). A malicious solution could consume all host resources.

### INFRA-3: Timeout is Robust (OK)

The `timeout --foreground {N}s` wrapping the Docker command (line 264) runs on the host and kills the container externally. This is reasonably robust and not easily circumventable.

---

## 5. Algorithmic Judge

The algorithmic track uses go-judge, which provides **significantly better isolation** than the research track.

### ALG-1: go-judge Provides Proper Sandboxing (GOOD)

- Whitelisted file access: solutions only see files in `copyIn`
- CPU/memory/process limits per test case
- Minimal environment (`PATH=/usr/bin:/bin`)
- Input via stdin, no access to .ans files

### ALG-2: Unauthenticated API Exposes Test Data (HIGH)

The judge server API has **no authentication**. The `/package/:pid` endpoint returns a tar.gz of the entire problem directory including checker source, test data, and answer files. Also available:
- `POST /submissions/reset` — reset all submissions
- `POST /problem/setup` / `POST /problem/add-problem` — modify problems

Solutions inside go-judge cannot access the network, so this is only exploitable by external actors with network access to port 8081.

### ALG-3: Checker Division-by-Zero Bugs (MEDIUM)

**Affected**: Problems 158 (Line Cutting), 164 (Stack Sorting)

Both checkers use `(best_value - baseline_value)` as a denominator without checking for zero. If `best_value == baseline_value`, this produces NaN/infinity. Problem 1's checker correctly handles this case, but 158 and 164 do not.

### ALG-4: Checker Buffer Overflow (LOW)

**Affected**: Problem 214 (Splay Reversal)

`chk.cc` has `t[MAX]` where `MAX=2000` (line 31) but reads N from input without bounds checking (line 123). If N > ~1998, the checker itself has a buffer overflow.

### ALG-5: Checker Precision Issues (LOW)

**Affected**: Problem 179 (Subset Sum BigInt)

The `BigInt::sub()` function assumes `a >= b` (line 53). If the subset sum is very far from target, `sub` produces incorrect intermediate results. The final clamp may mask this.

### ALG-6: Privileged Docker Container (LOW)

`docker-compose.yml` runs with `privileged: true` (required by go-judge for cgroups). This is necessary for the sandboxing to work but increases the blast radius of any container escape.

---

## 6. Full Issue Table

| ID | Severity | Vulnerability | Affected Problems |
|----|----------|---------------|-------------------|
| **CC-1** | CRITICAL | Arbitrary code execution at solution load time | All ~110 research variants |
| **CC-2** | CRITICAL | Monkey-patch timing, correctness, scoring functions | All ~110 research variants |
| **CC-3** | CRITICAL | Evaluator code writable in `/work/` | All ~110 research variants |
| **CC-4** | CRITICAL | Score injection via stdout | All ~110 research variants |
| **CC-5** | CRITICAL | Docker-in-Docker mounts host socket | poc_generation (~60 variants) |
| **NBod-1** | CRITICAL | Binary self-reports correctness | nbody_simulation (2 variants) |
| **SR-1** | CRITICAL | Solution self-reports complexity | symbolic_regression (5 variants) |
| **IMG-1** | CRITICAL | Test dataset reconstructible from seeds | imagenet_pareto (5 variants) |
| **GPU-3** | HIGH | atol=0.5 tolerance | fused_linear_ce, fused_linear_jsd |
| **GPU-4** | HIGH | 1x speedup = 100 points | qknorm |
| **GPU-6** | HIGH | program_path loads arbitrary code | All 21 GPU kernel problems |
| **SQL-1** | HIGH | Writable baseline cache poisons scoring | llm_sql (2 variants) |
| **SR-2** | HIGH | Solution can memorize test data | symbolic_regression (5 variants) |
| **IMG-2** | HIGH | Writable score_config.json | imagenet_pareto + vdb_pareto (10 variants) |
| **VDB-1** | HIGH | Ground truth accessible | vdb_pareto (5 variants) |
| **FUZZ-1** | HIGH | Coverage tracker manipulable via callback | grammar_fuzzing/fuzzer (1) |
| **CBL-1** | HIGH | Monkey-patchable cost constants | cant_be_late (24 variants) |
| **INFRA-1** | HIGH | No network isolation | All ~110 research variants |
| **ALG-2** | HIGH | Unauthenticated API exposes answers | All ~172 algorithmic problems |
| **GPU-1** | MEDIUM | Solution can delegate to baseline | All 21 GPU kernel problems |
| **GPU-2** | MEDIUM | Asymmetric FP32 baseline vs FP16 answer | 5 GPU kernel problems |
| **GPU-5** | MEDIUM | Fixed seeds enable precomputation | All 21 GPU kernel problems |
| **SQL-2** | MEDIUM | Solution receives full eval data | llm_sql (2 variants) |
| **SR-3** | MEDIUM | Reference metrics readable | symbolic_regression (5 variants) |
| **FUZZ-2** | MEDIUM | Source code access in seed variant | grammar_fuzzing/seed (1) |
| **CBL-2** | MEDIUM | Trace data readable | cant_be_late (24 variants) |
| **CC-1a** | MEDIUM | Cloudcast: two-stage code execution | cloudcast (1) |
| **POC-1** | MEDIUM | Network-dependent evaluation | poc_generation (~60 variants) |
| **INFRA-2** | MEDIUM | No memory/CPU limits | All ~110 research variants |
| **ALG-3** | MEDIUM | Checker division-by-zero | algorithmic/158, algorithmic/164 |
| **GPU-7** | LOW | Sequential Python baseline inflates speedup | mamba2_scan |
| **GPU-8** | LOW | CPU baseline in GPU scoring | vector_addition (3 variants) |
| **CBL-3** | LOW | Trivial validation string check | cant_be_late (24 variants) |
| **ROUTER-1** | LOW | Score not clamped to [0,100] | llm_router (1) |
| **ALG-4** | LOW | Checker buffer overflow | algorithmic/214 |
| **ALG-5** | LOW | Checker BigInt precision | algorithmic/179 |
| **ALG-6** | LOW | Privileged Docker container | All ~172 algorithmic problems |
| **POC-2** | BUG | Missing `import sys` in poc_evaluator.py | poc_generation (~60 variants) |

---

## 7. Affected Problem Matrix

Each cell shows the most severe vulnerability applicable. **C** = Critical, **H** = High, **M** = Medium, **L** = Low, **--** = not applicable.

| Problem | CC-1/2/3/4 (No Isolation) | Problem-Specific | Worst |
|---------|:---:|---|:---:|
| **flash_attn** | C | GPU-2 (FP32/FP16 asymmetry, M) | **C** |
| **cross_entropy** | C | -- | **C** |
| **group_gemm** | C | -- | **C** |
| **mixed_gemm** | C | GPU-2 (M) | **C** |
| **decoding_attn** | C | GPU-2 (M) | **C** |
| **gdpa_attention** | C | GPU-2 (M) | **C** |
| **ragged_attention** | C | GPU-2 (M) | **C** |
| **mamba2_scan** | C | GPU-7 (sequential baseline, L) | **C** |
| **qknorm** | C | GPU-4 (1x=100pts, H) | **C** |
| **quant_dot_int4** | C | -- | **C** |
| **fused_linear_ce** | C | GPU-3 (atol=0.5, H) | **C** |
| **fused_linear_jsd** | C | GPU-3 (atol=0.5, H) | **C** |
| **vector_addition/** (x3) | C | GPU-8 (CPU baseline, L) | **C** |
| **gemm_optimization/** (x6) | C | -- | **C** |
| **nbody_simulation/** (x2) | C | NBod-1 (self-report correctness, C) | **C** |
| **llm_sql/** (x2) | C | SQL-1 (cache poison, H) | **C** |
| **llm_router** | C | ROUTER-1 (unclamped score, L) | **C** |
| **symbolic_regression/** (x5) | C | SR-1 (self-report complexity, C), SR-2 (memorize data, H) | **C** |
| **imagenet_pareto/** (x5) | C | IMG-1 (reconstructible test set, C), IMG-2 (writable config, H) | **C** |
| **cloudcast** | C | CC-1a (two-stage exec, M) | **C** |
| **cant_be_late/** (x12) | C | CBL-1 (patchable costs, H) | **C** |
| **cant_be_late_multi/** (x12) | C | CBL-1 (H) | **C** |
| **grammar_fuzzing/fuzzer** | C | FUZZ-1 (manipulable tracker, H) | **C** |
| **grammar_fuzzing/seed** | C | FUZZ-2 (source access, M) | **C** |
| **vdb_pareto/** (x5) | C | IMG-2 (writable config, H), VDB-1 (GT access, H) | **C** |
| **poc_generation/** (~60) | C | CC-5 (DinD host escape, C), POC-1 (network dep, M) | **C** |
| **algorithmic/** (~172) | -- | ALG-2 (unauth API, H), ALG-3 (checker bugs, M) | **H** |

**Every single research problem has at least one Critical vulnerability** due to the shared infrastructure (CC-1 through CC-4).

---

## 8. Recommendations

### Immediate (fixes the critical issues):

1. **Run solution code in a subprocess with no shared memory.** The solution should execute in a child process that communicates results via a pipe or file. The evaluator process should be isolated from the solution's address space. This fixes CC-1 and CC-2.

2. **Keep evaluator code on a read-only mount.** Instead of `cp -r /workspace/* /work/`, mount the evaluator directory separately as read-only and only copy the solution to `/work/`. This fixes CC-3.

3. **Write scores to a file, not stdout.** Have the evaluator write to a designated file (e.g., `/tmp/_frontier_score.json`) on a tmpfs, and have the runner read from there. This fixes CC-4.

4. **Remove Docker socket mounting for DinD.** Use a sidecar container pattern or rootless Docker instead. This fixes CC-5.

5. **Add `--network=none` to Docker run commands** for all problems that don't require network access. This fixes INFRA-1.

### High Priority:

6. **Evaluator-side correctness verification for nbody.** The evaluator should independently verify the simulation output, not trust the binary's self-reported `correct` flag. This fixes NBod-1.

7. **Don't let solutions self-report complexity.** Remove the `details.get("complexity")` path in symbolic regression. Always compute complexity from the parsed expression. This fixes SR-1.

8. **Use non-deterministic seeds for test data** (or at minimum, don't publish them in the evaluator source). This fixes IMG-1 and GPU-5.

9. **Protect config files.** Move `score_config.json` and `baseline_cache.json` to read-only paths that the solution cannot write to. This fixes IMG-2 and SQL-1.

10. **Fix qknorm scoring.** Change to `score = 100 * (speedup - 1.0) / (target_speedup - 1.0)` or similar. This fixes GPU-4.

11. **Tighten fused_linear_ce/jsd tolerance.** `atol=0.5` is far too loose. Use `atol=1e-3` or similar. This fixes GPU-3.

12. **Authenticate the algorithmic judge API.** Add API key or token authentication. Remove or protect the `/package/:pid` endpoint. This fixes ALG-2.

### Medium Priority:

13. **Fix checker division-by-zero** in problems 158 and 164.
14. **Fix checker buffer overflow** in problem 214.
15. **Add memory/CPU limits** to Docker containers.
16. **Fix the missing `import sys`** in `poc_evaluator.py`.
17. **Clamp llm_router score** to [0, 100].
18. **Use consistent precision** for baseline vs answer timing in GPU problems.
