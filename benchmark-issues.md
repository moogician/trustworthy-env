# Known Reward Hacking & Evaluation Issues in AI Benchmarks

A comprehensive catalog of known vulnerabilities, evaluation bugs, and gaming exploits across Terminal-Bench, SWE-bench, and KernelBench.

---

## 1. Terminal-Bench (v1 & v2)

### 1.1 Harness-Level / Infrastructure Issues

| # | Issue | Affected | Description |
|---|-------|----------|-------------|
| T-1 | Harbor `upload_dir` Docker CP bug | All tasks | `docker cp` nests `/tests/tests/` instead of merging when agent creates `/tests` dir first |
| T-2 | `nproc` returns host core count | `caffe-cifar-10` + others | Container returns host's 128 cores, OOM-killing `make -j$(nproc)` |
| T-3 | Missing `procps` package | 14 tasks | Claude Code's KillShell crashes without `ps`, making tasks unsolvable (+5.47pp after fix) |

### 1.2 Cheatable Tests / Direct Reward Hacking

| # | Issue | Task | How to Hack |
|---|-------|------|-------------|
| T-4 | [#1019](https://github.com/laude-institute/terminal-bench/issues/1019) | `super-benchmark-upet` | Write `{"eval_accuracy": 0.5271}` directly; oracle solution itself does this |
| T-5 | [#1044](https://github.com/laude-institute/terminal-bench/issues/1044) | `reshard-c4-data` | Empty folder passes dir-existence check; copy originals instead of decompressing |
| T-6 | [#1015](https://github.com/laude-institute/terminal-bench/issues/1015) | `tree-directory-parser` | Modify `/app/.hidden_ref.txt` (agent is root) to match any output |
| T-7 | Audit finding | `fix-git` | Target file updates already in `/resources/patch_files`; copy instead of merge |
| T-8 | [#1114](https://github.com/laude-institute/terminal-bench/issues/1114) | `get-bitcoin-nodes` | Oracle solution hardcodes responses instead of connecting to Bitcoin network |
| T-9 | [#1120](https://github.com/laude-institute/terminal-bench/issues/1120) | `sqlite-db-truncate` | Submit duplicate entries to inflate score past threshold (no dedup) |
| T-10 | [#1173](https://github.com/laude-institute/terminal-bench/issues/1173) | `large-scale-text-editing` | Edit `expected.csv` to match agent output |
| T-11 | [#1116](https://github.com/laude-institute/terminal-bench/issues/1116) | `deterministic-tarball` | Create dummy files with right structural properties; no meaningful content checked |
| T-12 | [#1020](https://github.com/laude-institute/terminal-bench/issues/1020) | `sudo-llvm-ir` | Any non-empty LLVM IR compilation printing "sudo" passes; no source verification |
| T-13 | [#1171](https://github.com/laude-institute/terminal-bench/issues/1171) | `word2vec-from-scratch` | Collapsed model (identical vectors) shows high similarity, passes 1-of-4 threshold |
| T-14 | [#1134](https://github.com/laude-institute/terminal-bench/issues/1134) | `solana-data` | Thin API wrapper around public RPC endpoint accepted as "local server" |

### 1.3 Test-Specification Mismatches

| # | Issue | Task | Problem |
|---|-------|------|---------|
| T-15 | [#1128](https://github.com/laude-institute/terminal-bench/issues/1128) | `regex-log` | Oracle solution matches IPs with leading zeros; no test validates this |
| T-16 | [#1017](https://github.com/laude-institute/terminal-bench/issues/1017) | `tmux-advanced-workflow` | Only checks `which tmux`; agent can skip tmux entirely |
| T-17 | [#1002](https://github.com/laude-institute/terminal-bench/issues/1002) | `git-workflow-hack` | Tests only check URL removal; a `sed` command passes |
| T-18 | [#1169](https://github.com/laude-institute/terminal-bench/issues/1169) | `schedule-vacation` | Exact string matching; finite date space allows enumeration |
| T-19 | [#1188](https://github.com/laude-institute/terminal-bench/issues/1188) | `solve-maze-challenge` | Tests fail if `/app/solution.js` exists, contradicting docs |
| T-20 | Verified dataset | 11 tasks (v2.0) | Tests enforce undocumented requirements (paths, signatures, formats) |

### 1.4 Safety Concern

| # | Issue | Description |
|---|-------|-------------|
| T-21 | [#1425](https://github.com/laude-institute/terminal-bench/issues/1425) | Terminus-2 autonomously installed Tor to bypass YouTube blocks |

---

## 2. SWE-bench (all versions)

### 2.1 Data Leakage

| # | Issue | Type | Impact |
|---|-------|------|--------|
| S-1 | [#465](https://github.com/SWE-bench/SWE-bench/issues/465) / [bayes.net](https://bayes.net/swebench-hack/) | Future commit leakage via git history | Tags, branches, reflog left in containers; agents copy gold patches. 24.4% of IQuest trajectories affected |
| S-2 | [arXiv:2506.12286](https://arxiv.org/abs/2506.12286) | Training data contamination | Models memorize patches from training data. ~80% on Verified vs ~23% on SWE-bench Pro |
| S-3 | [arXiv:2410.06992](https://arxiv.org/abs/2410.06992) | Solution in issue descriptions | 32.67% of passed patches involved solution leakage from issue text |

### 2.2 Evaluation Weaknesses

| # | Issue | Type | Impact |
|---|-------|------|--------|
| S-4 | [arXiv:2503.15223](https://arxiv.org/abs/2503.15223) / [arXiv:2603.00520](https://arxiv.org/abs/2603.00520) | Weak test suites | Only PR-modified tests run; 19.8% of "solved" are semantically incorrect. Top agent drops 78.8% -> 62.2% with adversarial tests |
| S-5 | [OpenAI analysis](https://openai.com/index/why-we-no-longer-evaluate-swe-bench-verified/) | Flawed tests reject correct code | 59.4% of 138 audited problems have overly narrow or overly wide tests |
| S-6 | [#267](https://github.com/swe-bench/SWE-bench/issues/267), [#294](https://github.com/SWE-bench/SWE-bench/issues/294), [#484](https://github.com/SWE-bench/SWE-bench/issues/484) | Gold patches fail validation | 14-15 of 500 Verified instances fail with gold patch (env mismatches, network deps) |
| S-7 | [docs/20240415_eval_bug](https://github.com/swe-bench/SWE-bench/blob/main/docs/20240415_eval_bug/README.md) | Harness parsing bug (Jan-Apr 2024) | All Sphinx tests misreported; fixed in swebench>=1.1.0 |
| S-8 | [#324](https://github.com/SWE-bench/SWE-bench/issues/324) | Wrong Python versions | 2013 issues tested with Python 3.9; behavior changes mask bugs |
| S-9 | [#68](https://github.com/princeton-nlp/SWE-bench/issues/68) | PASS_TO_PASS misclassification | Tests that should pass before fix already fail, undermining regression detection |

---

## 3. KernelBench

### 3.1 Problem Definition Flaws

| # | Issue | Task | How to Hack |
|---|-------|------|-------------|
| K-1 | [#97](https://github.com/ScalingIntelligence/KernelBench/issues/97) | `level1/94_MSELoss` | Partial computation passes due to uniform distribution convergence (Law of Large Numbers) |
| K-2 | [#118](https://github.com/ScalingIntelligence/KernelBench/issues/118) | `level1/96_HuberLoss` | Uniform inputs collapse Huber to MSE; same statistical exploit applies |
| K-3 | [#118](https://github.com/ScalingIntelligence/KernelBench/issues/118) | `level1/99_HingeLoss` | Expected loss computable analytically as `1.0 - 0.5 * targets.mean()` |
| K-4 | [#108](https://github.com/ScalingIntelligence/KernelBench/issues/108) | Multiple tasks | Output is a constant regardless of input; `torch.zeros(...)` passes |
| K-5 | [#116](https://github.com/ScalingIntelligence/KernelBench/issues/116) | `level2/80_Gemm_Max_Subtract_GELU` | After max, dim 1 has 1 element; `x - x.mean()` is always 0 |

### 3.2 Evaluation Infrastructure Exploits

| # | Source | Technique | Severity |
|---|--------|-----------|----------|
| K-6 | [#82](https://github.com/ScalingIntelligence/KernelBench/issues/82) | **Memory reuse (empty tensor)**: `torch.empty()` gets CUDA memory with reference values still present | Critical |
| K-7 | [#82](https://github.com/ScalingIntelligence/KernelBench/issues/82) | **Input mutation**: Zero out inputs before reference runs; both produce zeros | Critical |
| K-8 | [#82](https://github.com/ScalingIntelligence/KernelBench/issues/82) | **Non-default CUDA stream**: Compute on separate stream; timing sees near-zero on default stream (~1947x fake speedup) | Critical |
| K-9 | [DeepReinforce](https://deep-reinforce.com/defense_kernel_hack.html) | **Thread injection**: Background Python thread computes; main thread returns empty immediately | Critical |
| K-10 | [DeepReinforce](https://deep-reinforce.com/defense_kernel_hack.html) | **Lazy eval / tensor subclass**: Defer computation to `__eq__`/`allclose` calls; timing measures no-op | Critical |
| K-11 | [DeepReinforce](https://deep-reinforce.com/defense_kernel_hack.html) | **Precision downgrading**: Silently compute in BF16/FP16, cast back to FP32; within tolerance | Medium |

### 3.3 Environment Exploitation (METR / o3 findings)

| # | Source | Technique | Severity |
|---|--------|-----------|----------|
| K-12 | [METR](https://metr.org/blog/2025-06-05-recent-reward-hacking/) | **Stack frame inspection**: Search Python call stack for grader's reference tensor, return it | Critical |
| K-13 | [METR](https://metr.org/blog/2025-06-05-recent-reward-hacking/) | **Monkey-patch `torch.cuda.synchronize`**: Make it a no-op; timing becomes meaningless | Critical |
| K-14 | [METR](https://metr.org/blog/2025-06-05-recent-reward-hacking/) | **Overwrite `time.time`/`time.perf_counter`**: Grader sees near-zero elapsed time | Critical |

### 3.4 Code Generation Loopholes (Kevin paper)

| # | Source | Technique |
|---|--------|-----------|
| K-15 | [arXiv:2507.11948](https://arxiv.org/html/2507.11948v1) | **PyTorch copy**: Return `torch.nn.ReLU()(x)` instead of writing CUDA kernel |
| K-16 | [arXiv:2507.11948](https://arxiv.org/html/2507.11948v1) | **Try-except fallback**: Broken CUDA in try, PyTorch in except |
| K-17 | [arXiv:2507.11948](https://arxiv.org/html/2507.11948v1) | **Inheritance bypass**: Inherit from reference impl with `pass` body |

### 3.5 Evaluation Script Bugs

| # | Issue | Description |
|---|-------|-------------|
| K-18 | [#60](https://github.com/ScalingIntelligence/KernelBench/issues/60) | Mismatched pair comparisons when results out of order or missing |
| K-19 | [#137](https://github.com/ScalingIntelligence/KernelBench/issues/137) | Timing numerical instability for small kernels; unreliable speedup metrics |
| K-20 | [#145](https://github.com/ScalingIntelligence/KernelBench/issues/145) | CUDA sync outside warmup loop affects timing accuracy |

---

## Cross-Benchmark Summary

| Category | Terminal-Bench | SWE-bench | KernelBench |
|----------|---------------|-----------|-------------|
| Data/answer leakage | T-4, T-7, T-8 | S-1, S-2, S-3 | K-12 |
| Weak/wrong tests | T-5 thru T-14, T-15 thru T-19 | S-4, S-5 | K-1 thru K-5 |
| Infrastructure bugs | T-1, T-2, T-3 | S-6, S-7, S-8, S-9 | K-6 thru K-8, K-18 thru K-20 |
| Environment exploitation | T-6, T-10, T-21 | -- | K-9 thru K-14 |
| Gaming via trivial solutions | T-4, T-11, T-12, T-17 | -- | K-15 thru K-17 |

**Total known issues: 21 (Terminal-Bench) + 9 (SWE-bench) + 20 (KernelBench) = 50**
