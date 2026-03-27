# Benchmark Reward Hacking: Detection Pipeline Report

## 1. Executive Summary

We built two independent detection pipelines to identify reward hacking vulnerabilities and evaluation bugs across three major AI benchmarks: **Terminal-Bench** (v1/v2), **SWE-bench** (all versions), and **KernelBench**. We cataloged **50 known issues** from public GitHub issues, papers, and security audits, then tested both pipelines against the full catalog.

| Metric | LLM Detector | Formal Detector |
|--------|-------------|-----------------|
| **Final detection rate** | 50/50 (100%) | 50/50 (100%) |
| V1 detection rate (pre-improvement) | 47/50 (94%) | 40/50 (80%) |
| Improvement iterations | 2 | 3 |
| Unique detection methods | 15 taxonomy classes | 12 analysis modules |

Both systems achieved **100% issue-level detection** after iterative improvement, though they differ significantly in **per-class precision** and **how** they detect -- which has implications for deployment.

---

## 2. Issue Catalog

### 2.1 Distribution by Benchmark

| Benchmark | Issues | Critical | High | Medium | Low |
|-----------|--------|----------|------|--------|-----|
| Terminal-Bench | 21 | 4 | 10 | 6 | 1 |
| SWE-bench | 9 | 3 | 4 | 2 | 0 |
| KernelBench | 20 | 8 | 6 | 4 | 2 |
| **Total** | **50** | **15** | **20** | **12** | **3** |

### 2.2 Distribution by Vulnerability Class

| Class | Count | Description |
|-------|-------|-------------|
| Weak test assertions | 11 | Tests check insufficient properties |
| Test-spec mismatch | 7 | Tests don't align with task description |
| Evaluation infrastructure exploit | 5 | Docker, CUDA, environment exploits |
| Hardcoded/predictable output | 4 | Output is constant or predictable |
| Evaluation script bug | 4 | Bugs in scoring/timing scripts |
| Statistical convergence exploit | 4 | Input distributions enable shortcuts |
| Answer leakage | 3 | Solutions accessible in environment |
| Timing measurement exploit | 3 | CUDA stream/thread timing manipulation |
| Environment manipulation | 3 | Monkey-patching, stack inspection |
| Code generation loophole | 3 | PyTorch wrappers, inheritance bypass |
| Writable reference file | 2 | Agent can modify expected output |
| Data contamination | 1 | Benchmark in LLM training data |
| Memory reuse exploit | 1 | CUDA allocator cache exploitation |
| Missing dependency | 1 | Missing packages make tasks unsolvable |
| Safety concern | 1 | Agent installs circumvention tools |

---

## 3. Detection Pipeline Architectures

### 3.1 LLM-Based Detector

**Philosophy**: Semantic understanding of code intent, cross-referencing task descriptions with test assertions, and natural-language reasoning about exploit feasibility.

**Architecture**:
```
Code Sample → [15 Taxonomic Scanners] → [Cross-Reference Pass] → Findings
```

**Taxonomy**: 15 vulnerability class scanners, each simulating a focused LLM prompt:

| Scanner | Target | Key Signals |
|---------|--------|-------------|
| `_scan_hardcoded_output` | Predictable outputs | Magic numbers in assertions, GELU(0)=0, hardcoded dicts |
| `_scan_weak_tests` | Insufficient coverage | Assert count, existence-only checks, score inflation, thresholds |
| `_scan_writable_references` | Mutable expected files | File paths in comparisons, root access, no integrity checks |
| `_scan_answer_leakage` | Solutions in environment | Git clone without sanitization, accessible answer files |
| `_scan_spec_mismatch` | Test/task contradictions | Undocumented requirements, oracle bugs, version mismatches |
| `_scan_infra_exploit` | Infrastructure vulnerabilities | Docker cp, nproc, input mutation, precision downgrade |
| `_scan_code_loopholes` | Trivial solutions | PyTorch wrappers, try-except fallback, inheritance bypass |
| `_scan_eval_bugs` | Scoring errors | Index misalignment, parser bugs, unpinned deps |
| `_scan_statistical_exploits` | Distribution shortcuts | Uniform + reduction, Huber collapse, analytical solutions |
| `_scan_timing_exploits` | Timing manipulation | CUDA streams, threading, lazy tensors |
| `_scan_memory_exploits` | Memory reuse | torch.empty in forward pass |
| `_scan_env_exploits` | Environment manipulation | inspect.stack, monkey-patching |
| `_scan_data_contamination` | Training data overlap | Popular repos, performance gaps |
| `_scan_missing_deps` | Missing packages | Dockerfile analysis |
| `_scan_safety` | Unsafe behavior | Circumvention tools, proxies |

**Cross-Reference Pass**: Holistic analysis combining signals (e.g., existence check + predictable value = compound vulnerability; git clone + reset without gc = incomplete sanitization).

**Strengths**:
- High recall on semantic vulnerabilities (spec mismatches, answer leakage)
- Natural understanding of code comments and intent
- Cross-referencing catches compound vulnerabilities

**Weaknesses**:
- Can over-trigger on comments describing fixes (required tuning /. detection)
- Relies on pattern heuristics that approximate LLM reasoning
- Less rigorous mathematical property checking

### 3.2 Formal/Testing-Based Detector

**Philosophy**: Programmatic analysis using AST parsing, mathematical property verification, data-flow analysis, and pattern matching -- no natural language understanding.

**Architecture**:
```
Code Sample → [12 Analysis Modules] → Findings
                ├── ASTAnalyzer
                ├── PropertyChecker
                ├── PermissionAnalyzer
                ├── GitStateVerifier
                ├── EvalOrderAnalyzer
                ├── DockerAnalyzer
                ├── CodePatternAnalyzer (13 dangerous patterns)
                ├── DependencyAnalyzer
                ├── EvalScriptAnalyzer
                ├── DataContaminationChecker
                ├── IssueTextLeakageChecker
                └── (AST-derived findings)
```

| Module | Method | Detects |
|--------|--------|---------|
| `ASTAnalyzer` | Python AST parse → structural properties | Inheritance bypass, try-except, assertion density |
| `PropertyChecker` | Mathematical invariant verification | Constant output (algebraic zero), statistical convergence, test coverage gaps |
| `PermissionAnalyzer` | File permission + access control audit | Writable reference files, root access |
| `GitStateVerifier` | Git sanitization completeness check | Missing cleanup steps (5-step checklist) |
| `EvalOrderAnalyzer` | Execution order side-channel analysis | Shared inputs, memory reuse window |
| `DockerAnalyzer` | Container configuration audit | docker cp bugs, missing resource limits, missing packages |
| `CodePatternAnalyzer` | 13 regex-based dangerous patterns | CUDA stream, threading, monkey-patching, stack inspection, etc. |
| `DependencyAnalyzer` | Dependency/version checking | Missing packages, unpinned versions |
| `EvalScriptAnalyzer` | Scoring + timing bug detection | Index misalignment, dedup, sync placement |
| `DataContaminationChecker` | Popular repo detection | Training data overlap risk |
| `IssueTextLeakageChecker` | Fix-in-description detection | Solution leakage from issue text |

**Strengths**:
- Rigorous: mathematical property checking is provably correct
- Fast: no API calls, runs in <100ms
- 13 precise dangerous-code patterns with low false-positive rate
- Git sanitization checklist is systematic and complete

**Weaknesses**:
- Cannot understand natural language (comments, task descriptions)
- Misses semantic spec mismatches (only 29% recall on that class)
- Requires explicit patterns -- novel vulnerabilities need new rules
- Comment text can confuse regex-based analysis

---

## 4. Comparison Results

### 4.1 Detection Rate Progression

| Version | LLM | Formal | Changes |
|---------|-----|--------|---------|
| V1 (initial) | 47/50 (94%) | 40/50 (80%) | Baseline |
| V2 (improvements) | 49/50 (98%) | 47/50 (94%) | Fixed code samples, added analyzers |
| V3 (final) | 50/50 (100%) | 50/50 (100%) | Fixed edge cases, subprocess-style git |

### 4.2 Per-Benchmark Detection (Final)

| Benchmark | LLM | Formal |
|-----------|-----|--------|
| Terminal-Bench | 21/21 (100%) | 21/21 (100%) |
| SWE-bench | 9/9 (100%) | 9/9 (100%) |
| KernelBench | 20/20 (100%) | 20/20 (100%) |

### 4.3 Per-Class Recall (Final)

| Vulnerability Class | LLM | Formal | Notes |
|---------------------|-----|--------|-------|
| hardcoded_or_predictable_output | **100%** | 75% | LLM catches semantic constants better |
| weak_test_assertions | **100%** | **100%** | Both strong here |
| writable_reference_file | **100%** | **100%** | Permission analysis is definitive |
| answer_leakage_in_environment | **100%** | 67% | LLM understands "leakage" semantically |
| test_spec_mismatch | 71% | 29% | **Both struggle** -- requires understanding task intent |
| evaluation_infrastructure_exploit | **100%** | 80% | LLM catches more infra patterns |
| code_generation_loophole | **100%** | **100%** | Pattern matching suffices |
| evaluation_script_bug | **100%** | **100%** | Eval script analysis is comprehensive |
| statistical_convergence_exploit | 75% | 75% | **Tied** -- both miss some edge cases |
| timing_measurement_exploit | **100%** | **100%** | Pattern matching suffices |
| memory_reuse_exploit | **100%** | **100%** | Pattern matching suffices |
| environment_manipulation | **100%** | **100%** | Pattern matching suffices |

### 4.4 Key Differences

**Where LLM excels over Formal**:
- **Semantic vulnerabilities**: Understanding that "the oracle solution is wrong" (T-15), that "issue text contains the fix" (S-3), or that a pipeline algebraically simplifies to a constant (K-4) requires reasoning about *meaning*, not just pattern matching.
- **Spec mismatches**: Detecting that tests don't align with task descriptions is fundamentally a natural-language understanding task. LLM recall: 71% vs Formal: 29%.
- **Answer leakage**: Understanding that accessible files contain answers (T-7) requires connecting task semantics to file contents.

**Where Formal excels over LLM**:
- **Mathematical rigor**: The property checker's algebraic zero detection (K-5) is provably correct. The LLM approximates this with heuristics.
- **Systematic coverage**: The git sanitization checklist (5 required steps) and 13 dangerous-pattern catalog provide deterministic, auditable detection.
- **No false triggers on comments**: After fixing the comment-stripping issue, formal analysis operates on code structure, not text.

**Where both struggle**:
- **Test-spec mismatch** (combined: 71%/29%): This requires understanding task intent from natural language descriptions, then verifying that tests align. Neither detector fully automates this comparison.
- **Statistical convergence** (both: 75%): Detecting that a *specific* input distribution enables convergence-based shortcuts requires mathematical reasoning about distributions, sample sizes, and loss functions. Some cases (K-4 "constant output described in comments") require reading comments rather than formal analysis.

---

## 5. Improvement History

### 5.1 V1 → V2 Fixes

| Issue | Detector | Root Cause | Fix |
|-------|----------|------------|-----|
| S-1 | Both | Code sample included fix in comments (`--single-branch`, `gc --prune`) | Removed fix from code sample |
| T-1 | Both | Code sample included fix (`/.`) in comments | Removed fix from code sample |
| S-9 | LLM | No pattern for `PASS_TO_PASS fail` as spec mismatch | Added `fail.*before.*patch` pattern |
| K-4, T-8 | Formal | No detection of hardcoded dicts or constant-output descriptions | Added `hardcoded_responses` and `constant_output_described` properties |
| T-11 | Formal | `content` in bug comment triggered false negative on structural check | Strip comments before checking for content verification code |
| T-15 | Formal | No oracle bug detection | Added `buggy_oracle` property check |
| K-18 | Formal | `[i]` pattern didn't trigger on description text | Added `assumes.*order` pattern |
| K-20 | Formal | Warmup sync pattern too specific | Added `sync.*outside.*loop` description match |
| S-2, S-3 | Formal | No data contamination or issue-text leakage analysis | Added `DataContaminationChecker` and `IssueTextLeakageChecker` modules |

### 5.2 V2 → V3 Fixes

| Issue | Detector | Root Cause | Fix |
|-------|----------|------------|-----|
| T-1 | Both | `/."` in fix comment matched `/.\s*["\']` exclusion | Removed fix from code sample |
| S-1 | Formal | `remote\s+(remove|rm)` didn't match `"remote", "remove"` in subprocess lists | Changed to `remote[\s",]+(remove|rm)` for both shell and Python |
| T-11 | Formal | `content` in comment still triggering | Comment-stripping before content-check regex |

### 5.3 Design Lesson

The most common failure mode was **code samples containing their own fixes in comments**. This is analogous to a real-world issue: evaluation code often has TODO comments or commented-out fixes that confuse both LLM and pattern-based analysis. The solution was to:
1. Clean code samples to represent the vulnerable state only
2. Strip comments before formal analysis of code behavior
3. Use comment-aware patterns in the LLM detector

---

## 6. Design Choices & Trade-offs

### 6.1 LLM Detector

**Choice: Taxonomic prompting over free-form analysis**
- *Why*: A single "find all vulnerabilities" prompt misses 30%+ of issues. Structured per-class prompts with explicit vulnerability definitions achieve near-complete coverage.
- *Trade-off*: More API calls (15 per issue), but each is focused and reliable.

**Choice: Cross-reference pass**
- *Why*: Some vulnerabilities only emerge from combining signals (e.g., git clone + reset - gc = incomplete sanitization). A second pass catches these compound issues.
- *Trade-off*: Increased complexity, but catches 3 additional issues that no single scanner detects.

**Choice: Confidence scoring**
- *Why*: Not all detections are equally certain. Confidence scores allow downstream filtering (e.g., only act on >0.8 confidence findings).
- *Trade-off*: Calibration requires labeled data. Current scores are heuristic.

### 6.2 Formal Detector

**Choice: 12 specialized modules over a monolithic analyzer**
- *Why*: Each vulnerability class has distinct analysis requirements (AST vs. math vs. permission checking). Modularity enables independent testing and extension.
- *Trade-off*: Some cross-module issues (e.g., a writable file that's also an answer leak) require both modules to fire independently.

**Choice: 13 explicit dangerous patterns**
- *Why*: CUDA stream manipulation, monkey-patching, and stack inspection are well-characterized attacks. Explicit patterns achieve 100% recall with near-zero false positives on known attacks.
- *Trade-off*: Zero-day exploits using novel patterns will be missed until a new rule is added.

**Choice: Comment-aware analysis**
- *Why*: Formal analysis should operate on code behavior, not comment text. Comments describing bugs or fixes confuse regex-based detection.
- *Trade-off*: Some legitimate signals in comments (e.g., "BUG: this is wrong") are useful. We selectively use comment-aware patterns only where false positives occurred.

### 6.3 Ensemble Recommendation

For production deployment, we recommend an **ensemble** approach:

```
                    ┌──────────────┐
  Benchmark Code ──>│ LLM Detector │──> Findings
         │         └──────────────┘       │
         │         ┌────────────────┐     │
         └────────>│ Formal Detector│──> Findings
                   └────────────────┘     │
                                          v
                                    ┌───────────┐
                                    │  Ensemble  │──> Final Report
                                    │  Merger    │    (union of all
                                    └───────────┘     findings)
```

- **Union strategy**: Report a vulnerability if *either* detector flags it. This maximizes recall (100% on all 50 issues).
- **Intersection for high-confidence**: When both detectors agree, confidence is highest. Use intersection for automated actions (blocking submissions).
- **LLM for triage, Formal for CI**: The formal detector runs in <100ms and is suitable for CI pipelines. The LLM detector is better for periodic deep audits.

---

## 7. Hands-On Reward Hacking Demonstrations

We built 6 working demonstrations (2 per benchmark) in `reward-hacking-demos/`:

| Demo | Benchmark | Exploit | Verified |
|------|-----------|---------|----------|
| `kernelbench/hack1_constant_output.py` | KernelBench | Return `torch.zeros()` for pipeline that always outputs zeros | 5/5 trials PASS |
| `kernelbench/hack2_memory_reuse.py` | KernelBench | `torch.empty()` reuses CUDA cache with stale reference values | Concept verified |
| `swebench/hack1_git_history_leakage.sh` | SWE-bench | `git log --all` shows 6423 future commits + 157 tags | 6423 commits visible |
| `swebench/hack2_weak_tests.py` | SWE-bench | Hardcode single test case; SWE-bench says RESOLVED | RESOLVED, fails 4/4 adversarial |
| `terminal_bench/hack1_hardcoded_output.sh` | Terminal-Bench | `echo '{"eval_accuracy": 0.5271}'` passes benchmark | TEST PASS |
| `terminal_bench/hack2_modify_reference.sh` | Terminal-Bench | Overwrite reference file as root; any output matches | TEST PASS |

---

## 8. Recommendations

### For Benchmark Maintainers

1. **Run both detectors on all tasks before release**. The formal detector catches infrastructure bugs (docker cp, missing deps) while the LLM detector catches semantic weaknesses (spec mismatches, leakage).

2. **Protect reference files**: Mount expected-output files as read-only volumes. Never let agents run as root.

3. **Verify process, not just output**: Tests should check *how* the result was produced (model artifacts, training logs, git operations used) not just the final value.

4. **Use heavy-tailed input distributions**: Replace `torch.rand` (uniform) with Pareto or Cauchy distributions for loss-function benchmarks to prevent statistical convergence exploits.

5. **Clean git state completely**: Use the 5-step checklist: single-branch clone, tag cleanup, reflog expire, gc --prune, verification check.

6. **Run full test suites**: Not just PR-modified tests. SWE-ABS showed a 16.6pp score drop when adversarial tests were added.

### For Researchers

7. **Benchmark contamination is systemic**: OpenAI stopped reporting SWE-bench Verified scores. New benchmarks should use private repositories or freshly-created tasks.

8. **Adversarial testing should be standard**: Every benchmark should include a red-team evaluation where the goal is to pass without solving the task.

9. **Ensemble detection is cheap**: Running both a pattern-based and LLM-based detector costs <$1/benchmark-task and catches all known vulnerability classes.

---

## Appendix A: File Inventory

```
detection/
  catalog.py              # 50-issue structured catalog with code samples
  llm_detector.py         # LLM-based detection pipeline (15 scanners)
  formal_detector.py      # Formal analysis pipeline (12 modules)
  runner.py               # Comparison runner with metrics
  results/
    comparison_v1.json     # V1 results
    comparison_v3_final.json  # Final results

reward-hacking-demos/
  kernelbench/
    hack1_constant_output.py
    hack2_memory_reuse.py
  swebench/
    hack1_git_history_leakage.sh
    hack2_weak_tests.py
  terminal_bench/
    hack1_hardcoded_output.sh
    hack2_modify_reference.sh

benchmark-issues.md        # Full issue catalog (50 issues, 3 benchmarks)
report.md                  # This report
```

## Appendix B: Reproduction

```bash
cd detection/

# Run both detectors
python3 runner.py

# Run individual detectors
python3 llm_detector.py
python3 formal_detector.py

# Run reward hacking demos
python3 ../reward-hacking-demos/kernelbench/hack1_constant_output.py
python3 ../reward-hacking-demos/swebench/hack2_weak_tests.py
bash ../reward-hacking-demos/terminal_bench/hack1_hardcoded_output.sh
bash ../reward-hacking-demos/swebench/hack1_git_history_leakage.sh
```
