# FrontierCS Benchmark: Vulnerability Scan Report

**Scanner**: `detection/detect.py` (LLM + Formal pipelines)
**Target**: https://github.com/FrontierCS/Frontier-CS (cloned at HEAD)
**Date**: 2026-03-28

## detect.py Raw Output Summary

```
Files scanned:  160
Files with findings: 160
Total findings: 391

By vulnerability class:
  safety_concern:                154  (mostly false positives from PoC "bypass" keywords)
  weak_test_assertions:           89
  code_generation_loophole:       43
  answer_leakage_in_environment:  26
  evaluation_script_bug:          19
  hardcoded_or_predictable_output:18
  memory_reuse_exploit:           18
  data_contamination:             10
  writable_reference_file:         8
  evaluation_infrastructure_exploit:3
  missing_dependency:              2
  statistical_convergence_exploit:  1
```

After manual triage: **154 `safety_concern` are false positives** (PoC generation problems legitimately contain security keywords). The remaining **237 findings** reduce to **5 distinct vulnerability classes** affecting specific problem groups.

---

## Vulnerability Summary

| ID | Vulnerability | Severity | Problems Affected | Similar Known Issue |
|----|--------------|----------|-------------------|---------------------|
| **F-1** | Writable evaluator/baseline after `cp -r /workspace/* /work/` | **Critical** | All research problems (~45) | T-6, T-10 (writable reference) |
| **F-2** | KernelBench-class timing/memory exploits | **High** | 18 GPU kernel problems | K-6, K-8, K-9, K-11 |
| **F-3** | Score injection via stdout | **High** | All research problems (~45) | T-4 (hardcoded output) |
| **F-4** | Generous tolerance enables precision downgrade | **Medium** | 18 GPU kernel problems | K-11 (precision downgrade) |
| **F-5** | Privileged Docker container for algorithmic judge | **Medium** | All algorithmic problems (~200+) | T-6 (root access) |

---

## F-1: Solution Can Modify Evaluator Code (Critical)

**Root cause**: `research_docker.py:_get_run_script()` copies everything to a writable directory before running evaluation:

```bash
cp -r /workspace/* /work/   # Everything becomes writable
cd /work
# ... evaluator.py, baseline.py, benchmark.py are now modifiable
./evaluate.sh               # Runs the (possibly modified) evaluator
```

The solution code runs via `evaluator.py` which `exec`s the solution module. The solution's `__init__` or `solve()` can modify files in `/work/` before evaluation occurs.

**Exploit**: A solution could overwrite `benchmark.py` or `baseline.py` to always return `pass_all=True` with a perfect score.

**All research problems are affected:**

| Problem | Evaluator File |
|---------|---------------|
| flash_attn | `research/problems/flash_attn/evaluator.py` |
| vector_addition/2_20 | `research/problems/vector_addition/2_20/evaluator.py` |
| vector_addition/2_24 | `research/problems/vector_addition/2_24/evaluator.py` |
| vector_addition/2_28 | `research/problems/vector_addition/2_28/evaluator.py` |
| cross_entropy | `research/problems/cross_entropy/evaluator.py` |
| group_gemm | `research/problems/group_gemm/evaluator.py` |
| gemm_optimization/squares | `research/problems/gemm_optimization/squares/evaluator.py` |
| gemm_optimization/rectangles | `research/problems/gemm_optimization/rectangles/evaluator.py` |
| gemm_optimization/near_tile | `research/problems/gemm_optimization/near_tile/evaluator.py` |
| gemm_optimization/k_skewed | `research/problems/gemm_optimization/k_skewed/evaluator.py` |
| gemm_optimization/annoying | `research/problems/gemm_optimization/annoying/evaluator.py` |
| gemm_optimization/transformerish | `research/problems/gemm_optimization/transformerish/evaluator.py` |
| mixed_gemm | `research/problems/mixed_gemm/evaluator.py` |
| flash_attn | `research/problems/flash_attn/evaluator.py` |
| decoding_attn | `research/problems/decoding_attn/evaluator.py` |
| gdpa_attention | `research/problems/gdpa_attention/evaluator.py` |
| ragged_attention | `research/problems/ragged_attention/evaluator.py` |
| mamba2_scan | `research/problems/mamba2_scan/evaluator.py` |
| qknorm | `research/problems/qknorm/evaluator.py` |
| quant_dot_int4 | `research/problems/quant_dot_int4/evaluator.py` |
| fused_linear_ce | `research/problems/fused_linear_ce/evaluator.py` |
| fused_linear_jsd | `research/problems/fused_linear_jsd/evaluator.py` |
| llm_sql/large | `research/problems/llm_sql/large/evaluator.py` |
| llm_sql/small | `research/problems/llm_sql/small/evaluator.py` |
| llm_router | `research/problems/llm_router/evaluator.py` |
| nbody_simulation/random_10k | `research/problems/nbody_simulation/random_10k/evaluator.py` |
| nbody_simulation/random_100k | `research/problems/nbody_simulation/random_100k/evaluator.py` |
| cloudcast | `research/problems/cloudcast/evaluator.py` |
| symbolic_regression/* (5 variants) | `research/problems/symbolic_regression/*/evaluator.py` |
| imagenet_pareto/* (5 variants) | `research/problems/imagenet_pareto/*/evaluator.py` |
| vdb_pareto/* (5 variants) | `research/problems/vdb_pareto/*/evaluator.py` |
| grammar_fuzzing/* (2 variants) | `research/problems/grammar_fuzzing/*/evaluator.py` |
| cant_be_late/* (8 variants) | `research/problems/cant_be_late/*/evaluator.py` |
| poc_generation/* (~60 variants) | `research/problems/poc_generation/*/evaluator.py` |

**Recommendation**: Keep evaluator code on a read-only mount separate from the solution workspace. Run the solution in a subprocess that cannot access the evaluator directory.

---

## F-2: KernelBench-Class Timing/Memory Exploits (High)

**Root cause**: GPU kernel problems use the same evaluation pattern as KernelBench (`torch.allclose` for correctness + `triton.testing.do_bench` for timing), inheriting the same exploit surface.

**Detected exploit vectors** (from `benchmark.py` files):

| Exploit | Mechanism | Detector | Confidence |
|---------|-----------|----------|------------|
| **Memory reuse** | `torch.empty` in allocator (line 15 of flash_attn benchmark.py) returns CUDA cache with stale reference values | FORMAL | 80% |
| **Try-except fallback** | `try/except` around kernel calls; fall back to PyTorch baseline | LLM+FORMAL | 80-85% |
| **CUDA stream manipulation** | `triton.testing.do_bench` measures default stream only | (known from KernelBench) | -- |
| **Precision downgrade** | flash_attn uses `rtol=1e-2, atol=5e-3` -- generous enough for fp16 shortcuts | (manual review) | -- |

**Affected problems** (all 18 GPU kernel problems):

| Problem | benchmark.py | Tolerance |
|---------|-------------|-----------|
| flash_attn | `resources/benchmark.py` | rtol=1e-2, atol=5e-3 |
| cross_entropy | `resources/benchmark.py` | (shared pattern) |
| group_gemm | `resources/benchmark.py` | (shared pattern) |
| mixed_gemm | `resources/benchmark.py` | (shared pattern) |
| decoding_attn | `resources/benchmark.py` | (shared pattern) |
| gdpa_attention | `resources/benchmark.py` | (shared pattern) |
| ragged_attention | `resources/benchmark.py` | (shared pattern) |
| mamba2_scan | `resources/benchmark.py` | (shared pattern) |
| qknorm | `resources/benchmark.py` | (shared pattern) |
| quant_dot_int4 | `resources/benchmark.py` | (shared pattern) |
| fused_linear_ce | `resources/benchmark.py` | (shared pattern) |
| fused_linear_jsd | `resources/benchmark.py` | (shared pattern) |
| vector_addition/2_20 | evaluator.py (inline) | rtol=1e-5, atol=1e-8 (tighter) |
| vector_addition/2_24 | evaluator.py (inline) | rtol=1e-5, atol=1e-8 (tighter) |
| vector_addition/2_28 | evaluator.py (inline) | rtol=1e-5, atol=1e-8 (tighter) |
| gemm_optimization/* (6 variants) | `resources/benchmark.py` | (shared pattern) |

**Note**: The vector_addition problems use significantly tighter tolerance (1e-5/1e-8 vs 1e-2/5e-3), making precision downgrade harder. The other 15 kernel problems use the looser tolerance.

**Recommendation**: Apply KernelBench's defenses -- clone inputs before passing to custom kernel, clear CUDA memory cache between reference and custom runs, flag excessive speedups, add static code checking for `torch.cuda.Stream`, `threading`, `inspect.stack`, etc.

---

## F-3: Score Injection via Stdout (High)

**Root cause**: `research_docker.py:_parse_score()` (lines 351-382) parses the score from the **last numeric line** of Docker stdout:

```python
def _parse_score(self, output: str):
    for line in reversed(lines):
        # Skip log messages
        if line.startswith("[") or "INFO" in line or "ERROR" in line:
            continue
        parts = line.split()
        try:
            score = float(parts[0])         # First number = bounded score
            score_unbounded = float(parts[1]) if len(parts) > 1 else score
            return score, score_unbounded, None
        except ValueError:
            continue
```

Since the solution module runs in the same process as the evaluator, it can print to stdout. If a solution's `solve()` method prints `"100 200"` and then causes the evaluator to crash before printing its own score, the parser would pick up the injected score.

**Affected**: All research problems (same runner).

**Recommendation**: Have the evaluator write the score to a file (e.g., `/tmp/score.json`) rather than stdout, and read from that file. Or run the solution in a subprocess with captured stdout.

---

## F-4: Generous Tolerance Enables Precision Downgrade (Medium)

**Root cause**: Most GPU kernel benchmarks use `rtol=1e-2, atol=5e-3` for `torch.allclose`. Computing in FP16 and casting back to FP32 can pass this tolerance while using tensor cores for significant speedup.

**Affected**: Same 15 kernel problems as F-2 (excluding vector_addition which uses 1e-5/1e-8).

**Recommendation**: Tighten tolerance for FP32 problems to `rtol=1e-4, atol=1e-4` (matching KernelBench). Or verify that the submitted kernel operates at the declared precision.

---

## F-5: Privileged Docker Container (Medium)

**Root cause**: `algorithmic/docker-compose.yml` runs with `privileged: true` (required by go-judge for sandboxing).

**Affected**: All algorithmic problems (200+).

**Risk**: While go-judge provides user-level sandboxing, a container escape from a privileged container grants full host access. This is a defense-in-depth concern, not a direct reward hacking vector.

**Recommendation**: Evaluate whether `--security-opt seccomp=...` or `--cap-add` with specific capabilities could replace full `privileged` mode.

---

## False Positive Analysis

| Class | Count | Why False Positive |
|-------|-------|--------------------|
| `safety_concern` | 154 | PoC generation problems legitimately contain "bypass", "exploit" keywords |
| `data_contamination` | 10 | Symbolic regression evaluators import `sympy`/`numpy`/`pandas` -- popular libs, not benchmark contamination |
| `evaluation_script_bug` (index) | 5 | Symbolic regression evaluators use `[i]` indexing but iterate correctly |
| `weak_test_assertions` (structural) | ~30 | Many are from `.py` files that use `Path.suffix` / `.name` for legitimate file handling |

---

## Problem-Level Impact Matrix

| Problem Category | Count | F-1 | F-2 | F-3 | F-4 | F-5 |
|-----------------|-------|-----|-----|-----|-----|-----|
| GPU kernel optimization | 18 | Y | **Y** | Y | **Y** | -- |
| Algorithmic (competitive) | ~200 | -- | -- | -- | -- | Y |
| PoC generation (security) | ~60 | Y | -- | Y | -- | -- |
| ML/AI (imagenet, cloudcast) | 6 | Y | -- | Y | -- | -- |
| Database (llm_sql) | 2 | Y | -- | Y | -- | -- |
| Systems (nbody, cant_be_late) | 10 | Y | -- | Y | -- | -- |
| Symbolic regression | 5 | Y | -- | Y | -- | -- |
| Vector DB (vdb_pareto) | 5 | Y | -- | Y | -- | -- |
| Grammar fuzzing | 2 | Y | -- | Y | -- | -- |
| LLM router | 1 | Y | -- | Y | -- | -- |

**F-1 (writable evaluator) and F-3 (stdout injection) affect ALL research problems.**
**F-2 and F-4 (timing/memory/precision) affect the 18 GPU kernel problems specifically.**
