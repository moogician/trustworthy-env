# Benchmark Audit System MVP

This repository now includes an implementation of the benchmark audit architecture in `detection/audit_mvp.py`, including explicit static and runtime verification stages.

## What it implements

- **Benchmark ingestor**
  - Scans a benchmark repo/problem directory.
  - Produces a normalized `BenchmarkSpec` with inferred entrypoints, hidden assets, score channel, and sandbox hints.
- **Static analyzer**
  - Applies policy checks for:
    - same-process submission loading,
    - stdout-derived scoring,
    - self-reported score fields,
    - hidden asset exposure,
    - Docker socket mounts,
    - missing network isolation.
- **Static verification (solver-backed)**
  - Extracts score formulas (`score = ...`) from Python evaluators.
  - Uses z3 (when available) to prove properties or find counterexamples for:
    - score bounds (`0 <= score <= 100`),
    - division-by-zero possibility in denominators.
- **Runtime verification**
  - Runs an optional benchmark command (`--run-cmd`) under instrumentation.
  - Uses `strace` when available to detect `connect()`/`openat()`/`execve()` signals.
  - Checks mutation of evaluator/checker/hidden files before vs after execution.
  - Flags suspicious stdout numeric-tail score patterns.
- **Adversarial test generator**
  - Produces a universal exploit template plan (stdout injection, monkey-patching, hidden-file scan, config poisoning, etc.).
- **Findings correlator**
  - Clusters findings into root causes and computes a benchmark risk score/band.

## CLI usage

Run the existing detector CLI with the new `audit` command:

```bash
python3 detection/detect.py audit <benchmark_path> --benchmark-id <name> --out report.json
python3 detection/detect.py audit <benchmark_path> --run-cmd "python3 evaluator.py" --timeout-s 120
```

Example:

```bash
python3 detection/detect.py audit kernelbench-demo --benchmark-id kernelbench --out artifacts/kernelbench-audit.json
```

## Output structure

The generated report JSON contains:

- `benchmark_spec`
- `findings`
- `static_verification`
- `runtime_verification`
- `exploit_plan`
- `summary` (risk score, risk band, root-cause clusters)

## Current scope and next steps

This is still an incremental implementation. Current limitations:

- runtime verification is command-driven (`--run-cmd`) and not yet a full three-container orchestrator,
- solver checks focus on arithmetic score formulas extractable as `score = ...`,
- no differential runner/metamorphic replay yet,
- no full LLM exploit agents yet.

Those can be added incrementally on top of this schema and command surface.
