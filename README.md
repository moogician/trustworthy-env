# Benchmark Audit Tool

<p align="center">
  <a href="#quick-start">Quick Start</a>
  ·
  <a href="#audit-pipeline">Audit Pipeline</a>
  ·
  <a href="#run-on-a-new-benchmark">Run on Benchmarks</a>
</p>

Automated security audit tool for AI benchmark evaluation infrastructure. It detects reward hacking vulnerabilities, evaluation bugs, and scoring exploits across AI benchmarks using a dual-engine approach: LLM-based semantic analysis and formal/static verification with Z3 solver-backed proofs.

> [!IMPORTANT]
> This tool requires Python 3.10+. Some features (semantic analysis, PoC verification) require an LLM API key — set `AUDIT_API_KEY`, `ANTHROPIC_API_KEY`, or `OPENAI_API_KEY` in your environment.

## Current repository shape

- **`detection/`** — core detection pipeline: dual LLM + formal engines, 8-stage audit system, exploit generator
- **`scripts/`** — automation scripts to clone and audit popular benchmarks end-to-end

## Quick start

```bash
# Scan a benchmark repo for vulnerabilities
python3 detection/detect.py scan path/to/benchmark/

# Scan a single file
python3 detection/detect.py scan path/to/eval_script.py

# Use only one detector
python3 detection/detect.py scan path/to/benchmark/ --detector formal
python3 detection/detect.py scan path/to/benchmark/ --detector llm

# Run the full audit pipeline (policy + static + runtime verification)
python3 detection/detect.py audit path/to/benchmark/ \
    --benchmark-id mybench \
    --out audit-report.json

# Include runtime verification
python3 detection/detect.py audit path/to/benchmark/ \
    --benchmark-id mybench \
    --run-cmd "python3 evaluator.py" \
    --timeout-s 90

# Verify findings with agentic PoC generation (requires LLM API key)
python3 detection/detect.py verify audit-report.json \
    --model vertex_ai/claude-opus-4-6

# Run regression test against all 50 known issues
python3 detection/detect.py test

# Show the built-in issue catalog
python3 detection/detect.py catalog
```

## Audit pipeline

The audit pipeline runs 8 sequential stages on a benchmark repository:

```
Benchmark Repo
    │
    ├── 1. Benchmark Ingestion ──────── parse structure, find eval scripts
    ├── 2. Static Policy Analysis ───── regex/pattern lint for policy violations
    ├── 3. Evaluator Code Analysis ──── AST + regex, 6 structural detectors
    ├── 4. Semantic Analysis ────────── LLM-based reasoning, 15 vulnerability scanners
    ├── 5. Static Verification ──────── Z3 solver proofs and counterexamples
    ├── 6. Runtime Verification ─────── strace + mutation testing
    ├── 7. Adversarial Test Gen ─────── 14 exploit templates, PoC generation
    └── 8. Findings Correlation ─────── risk scoring, root-cause clustering
            │
            ▼
      JSON report
```

The tool detects 15 vulnerability classes: hardcoded output, weak tests, writable references, answer leakage, spec mismatch, infra exploits, code loopholes, eval script bugs, statistical exploits, timing exploits, memory exploits, environment manipulation, data contamination, missing dependencies, and safety concerns.

## Run on a new benchmark

Use the generic `run_benchmark.sh` to audit any benchmark by its Git URL:

```bash
# Basic usage
bash scripts/run_benchmark.sh <benchmark-id> <git-repo-url> [subdirectory]

# Examples
bash scripts/run_benchmark.sh MMLU https://github.com/hendrycks/test.git
bash scripts/run_benchmark.sh HumanEval https://github.com/openai/human-eval.git
bash scripts/run_benchmark.sh BFCL https://github.com/ShishirPatil/gorilla.git berkeley-function-call-leaderboard
```

When an LLM API key is set, the script first runs an **LLM-based extraction step** (`detection/extract_benchmark.py`) that reads the repo's READMEs, configs, and eval scripts to identify the benchmark structure — problem directories, evaluator entrypoints, scoring mechanisms, hidden assets, and sandbox configuration. This produces a `.benchmark_spec.json` in the cloned repo that supplements the heuristic-based detection. You can also run extraction standalone:

```bash
python3 detection/extract_benchmark.py /path/to/benchmark --benchmark-id MyBench
```

The full pipeline then runs: scan, audit, and optionally PoC verification.

```bash
# With LLM-powered extraction + PoC verification
export AUDIT_API_KEY="sk-..."
export AUDIT_MODEL="vertex_ai/claude-opus-4-6"  # optional, defaults to gpt-4o-mini
bash scripts/run_benchmark.sh HumanEval https://github.com/openai/human-eval.git
```

## Run on pre-configured benchmarks

Pre-built scripts in `scripts/` automate the full cycle for several benchmarks:

```bash
# Run all pre-configured benchmarks
bash scripts/run_all.sh

# Run a specific one
bash scripts/run_agentbench.sh
bash scripts/run_agieval.sh
bash scripts/run_bfcl.sh
bash scripts/run_gaia.sh
bash scripts/run_livebench.sh
bash scripts/run_webarena.sh
```

Each script clones the benchmark repo, runs detection, executes the audit pipeline (writing a JSON report to `data/reports/`), and optionally runs agentic PoC verification if an LLM API key is set.

## License

[MIT](./LICENSE)
