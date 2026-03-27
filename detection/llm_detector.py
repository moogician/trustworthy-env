"""
LLM-Based Benchmark Vulnerability Detector
============================================
Uses structured LLM analysis to detect reward hacking vulnerabilities
in benchmark evaluation code. Operates by:

1. Taxonomic prompting: queries organized by vulnerability class
2. Chain-of-thought reasoning over code semantics
3. Cross-referencing task description vs test assertions
4. Multi-pass analysis (broad scan → targeted deep-dive)

In production, each analysis function would call an LLM API.
Here we implement the detection logic that the LLM prompts encode,
using pattern matching + semantic heuristics to simulate LLM-level
understanding. This lets us measure detection rates without API costs.

The prompt templates are preserved as docstrings for reproducibility.
"""

import ast
import re
import textwrap
from dataclasses import dataclass, field
from typing import Optional

from catalog import Issue, VulnClass, ALL_ISSUES


@dataclass
class Finding:
    """A single vulnerability detected by the LLM pipeline."""
    issue_id: str
    vuln_class: VulnClass
    confidence: float  # 0.0 - 1.0
    reasoning: str
    evidence: list[str] = field(default_factory=list)


@dataclass
class DetectionResult:
    """Full detection result for one issue."""
    issue_id: str
    findings: list[Finding] = field(default_factory=list)
    detected: bool = False

    def __post_init__(self):
        self.detected = len(self.findings) > 0


# ============================================================================
# LLM Prompt Templates (would be sent to API in production)
# ============================================================================

SYSTEM_PROMPT = """You are a security researcher specializing in AI benchmark
evaluation integrity. Analyze the provided benchmark code for reward hacking
vulnerabilities -- ways an AI agent could pass evaluation without genuinely
solving the task. For each vulnerability found, classify it and explain the
exploit mechanism."""

TAXONOMY_PROMPT = """Analyze this benchmark code for the following vulnerability classes:

1. HARDCODED_OUTPUT: Can the expected output be predicted without computation?
2. WEAK_TEST: Do tests check insufficient properties? Can wrong solutions pass?
3. WRITABLE_REFERENCE: Can the agent modify expected-output/reference files?
4. ANSWER_LEAKAGE: Are answers accessible in the environment (git history, files)?
5. SPEC_MISMATCH: Do tests enforce requirements not in the task description, or miss stated requirements?
6. INFRA_EXPLOIT: Can evaluation infrastructure be exploited (Docker, memory, timing)?
7. CODE_LOOPHOLE: Can the agent submit trivial code that delegates to the reference?
8. EVAL_SCRIPT_BUG: Are there bugs in evaluation/scoring scripts?
9. STATISTICAL_EXPLOIT: Can statistical properties of inputs be exploited?
10. TIMING_EXPLOIT: Can timing measurements be manipulated?
11. MEMORY_EXPLOIT: Can CUDA/memory allocation behavior be exploited?
12. ENV_EXPLOIT: Can the agent manipulate the evaluation environment (monkey-patching, stack inspection)?
13. DATA_CONTAMINATION: Is the benchmark likely in LLM training data?
14. MISSING_DEPENDENCY: Are there missing packages/tools that make tasks unsolvable?
15. SAFETY_CONCERN: Does the benchmark enable unsafe agent behavior?

For each vulnerability found, provide:
- Class (from above)
- Confidence (0.0-1.0)
- Exploit mechanism (how an agent would hack this)
- Evidence (specific code lines/patterns)
"""


# ============================================================================
# Detection Heuristics (simulating LLM reasoning)
# ============================================================================

class LLMDetector:
    """
    Simulates LLM-based vulnerability detection using the prompt taxonomy.
    Each method corresponds to a prompt template that would be sent to the LLM.
    """

    def analyze(self, issue: Issue) -> DetectionResult:
        """Run all analysis passes on an issue's code sample."""
        findings = []

        # Pass 1: Broad vulnerability scan
        findings.extend(self._scan_hardcoded_output(issue))
        findings.extend(self._scan_weak_tests(issue))
        findings.extend(self._scan_writable_references(issue))
        findings.extend(self._scan_answer_leakage(issue))
        findings.extend(self._scan_spec_mismatch(issue))
        findings.extend(self._scan_infra_exploit(issue))
        findings.extend(self._scan_code_loopholes(issue))
        findings.extend(self._scan_eval_bugs(issue))
        findings.extend(self._scan_statistical_exploits(issue))
        findings.extend(self._scan_timing_exploits(issue))
        findings.extend(self._scan_memory_exploits(issue))
        findings.extend(self._scan_env_exploits(issue))
        findings.extend(self._scan_data_contamination(issue))
        findings.extend(self._scan_missing_deps(issue))
        findings.extend(self._scan_safety(issue))

        # Pass 2: Cross-reference (LLM would do holistic reasoning)
        findings.extend(self._cross_reference_analysis(issue))

        # Deduplicate by vuln_class
        seen = set()
        unique = []
        for f in findings:
            if f.vuln_class not in seen:
                seen.add(f.vuln_class)
                unique.append(f)

        return DetectionResult(issue_id=issue.id, findings=unique)

    # --- Pass 1: Per-class scanners ---

    def _scan_hardcoded_output(self, issue: Issue) -> list[Finding]:
        """
        LLM prompt: "Can the expected output be predicted/hardcoded without
        doing the actual computation? Look for: single scalar checks,
        constant expected values, magic numbers in assertions."
        """
        findings = []
        code = issue.code_sample
        desc = issue.description.lower() + " " + issue.title.lower()

        # Pattern: specific numeric value in assertion
        if re.search(r'assert.*==\s*[\d.]+', code) or re.search(r'==\s*0\.\d{3,}', code):
            findings.append(Finding(
                issue_id=issue.id,
                vuln_class=VulnClass.HARDCODED_OUTPUT,
                confidence=0.85,
                reasoning="Test asserts exact numeric value; agent can write this directly",
                evidence=re.findall(r'assert.*==\s*[\d.]+', code),
            ))

        # Pattern: hardcoded response dict
        if re.search(r'HARDCODED|hardcode|pre-know', code, re.IGNORECASE):
            findings.append(Finding(
                issue_id=issue.id,
                vuln_class=VulnClass.HARDCODED_OUTPUT,
                confidence=0.9,
                reasoning="Code contains hardcoded responses matching test queries",
                evidence=["HARDCODED dict pattern found"],
            ))

        # Pattern: constant output (zeros, ones)
        if re.search(r'always\s+(zero|0|constant|same)', desc) or \
           re.search(r'torch\.zeros|output.*always', code, re.IGNORECASE):
            findings.append(Finding(
                issue_id=issue.id,
                vuln_class=VulnClass.HARDCODED_OUTPUT,
                confidence=0.9,
                reasoning="Output is mathematically constant regardless of input",
                evidence=["algebraic simplification to constant"],
            ))

        # Pattern: GELU(0) = 0 or x - x.mean = 0
        if re.search(r'x\s*-\s*x\.mean', code) and re.search(r'gelu', code, re.IGNORECASE):
            findings.append(Finding(
                issue_id=issue.id,
                vuln_class=VulnClass.HARDCODED_OUTPUT,
                confidence=0.95,
                reasoning="Pipeline: max(keepdim) -> subtract mean of single element (=0) -> GELU(0)=0",
                evidence=["x - x.mean(dim=1) on (B,1) tensor = 0", "GELU(0) = 0"],
            ))

        return findings

    def _scan_weak_tests(self, issue: Issue) -> list[Finding]:
        """
        LLM prompt: "Do the test assertions cover the full task requirements?
        Can a wrong solution pass all checks? Look for: single test cases,
        existence checks without content verification, threshold gaming."
        """
        findings = []
        code = issue.code_sample
        desc = issue.description.lower()

        # Pattern: os.path.isdir/exists without content check
        if re.search(r'os\.path\.(isdir|exists)', code) and \
           not re.search(r'os\.listdir|len\(|content|filecmp', code):
            findings.append(Finding(
                issue_id=issue.id,
                vuln_class=VulnClass.WEAK_TEST,
                confidence=0.85,
                reasoning="Existence check without content verification",
                evidence=["os.path.isdir/exists without listing contents"],
            ))

        # Pattern: score > N without deduplication
        if re.search(r'score\s*[><=]+\s*\d', code) and 'dedup' not in code.lower():
            if re.search(r'for.*in.*:', code) and re.search(r'score\s*\+=', code):
                findings.append(Finding(
                    issue_id=issue.id,
                    vuln_class=VulnClass.WEAK_TEST,
                    confidence=0.8,
                    reasoning="Score accumulation without deduplication allows inflation",
                    evidence=["score += in loop without dedup check"],
                ))

        # Pattern: only checks subset of task (simple string search)
        if re.search(r'not in content|sed|only.*check|only.*test', desc):
            findings.append(Finding(
                issue_id=issue.id,
                vuln_class=VulnClass.WEAK_TEST,
                confidence=0.75,
                reasoning="Test covers only a subset of the stated task requirements",
                evidence=["partial coverage detected"],
            ))

        # Pattern: len(x) > 0 as only validation
        if re.search(r'len\(.*\)\s*>\s*0|assert.*len.*>', code):
            findings.append(Finding(
                issue_id=issue.id,
                vuln_class=VulnClass.WEAK_TEST,
                confidence=0.7,
                reasoning="Non-empty check is trivially satisfiable",
                evidence=["len > 0 assertion"],
            ))

        # Pattern: very few test cases for a complex task
        assert_count = len(re.findall(r'assert\s', code))
        if assert_count <= 2 and 'test_' in code:
            findings.append(Finding(
                issue_id=issue.id,
                vuln_class=VulnClass.WEAK_TEST,
                confidence=0.65,
                reasoning=f"Only {assert_count} assertion(s) for task validation",
                evidence=[f"{assert_count} assert statements found"],
            ))

        # Pattern: low similarity threshold
        if re.search(r'>\s*0\.\d\b', code) and re.search(r'similarity|sim\s*>', code):
            findings.append(Finding(
                issue_id=issue.id,
                vuln_class=VulnClass.WEAK_TEST,
                confidence=0.8,
                reasoning="Similarity threshold too low; degenerate solutions pass",
                evidence=["low threshold on similarity metric"],
            ))

        # Pattern: only N-of-M required
        if re.search(r'>=\s*1\b', code) and re.search(r'passing|pass_count', code):
            findings.append(Finding(
                issue_id=issue.id,
                vuln_class=VulnClass.WEAK_TEST,
                confidence=0.8,
                reasoning="Only 1-of-N required to pass; degenerate solution can satisfy one",
                evidence=[">= 1 threshold on pass count"],
            ))

        # Pattern: structural checks without content (tarball, etc)
        if re.search(r'issym|isdir|endswith|\.name', code) and \
           re.search(r'BUG.*never.*content|BUG.*no.*content', code, re.IGNORECASE):
            findings.append(Finding(
                issue_id=issue.id,
                vuln_class=VulnClass.WEAK_TEST,
                confidence=0.85,
                reasoning="Tests check structural properties without verifying content",
                evidence=["structural checks only"],
            ))

        # Pattern: only PR-modified tests
        if re.search(r'PR.*test|only.*test.*from.*PR|FAIL_TO_PASS', code):
            findings.append(Finding(
                issue_id=issue.id,
                vuln_class=VulnClass.WEAK_TEST,
                confidence=0.9,
                reasoning="Only tests modified in the fixing PR are executed",
                evidence=["partial test suite execution"],
            ))

        # Pattern: tests too narrow or too wide
        if re.search(r'too narrow|too wide|overly strict', code, re.IGNORECASE):
            findings.append(Finding(
                issue_id=issue.id,
                vuln_class=VulnClass.WEAK_TEST,
                confidence=0.85,
                reasoning="Test assertions are overly narrow (reject correct) or overly wide (accept wrong)",
                evidence=["test precision/recall mismatch with task scope"],
            ))

        return findings

    def _scan_writable_references(self, issue: Issue) -> list[Finding]:
        """
        LLM prompt: "Can the agent modify reference/expected output files?
        Look for: comparisons against files in agent-writable directories,
        root permissions, no file integrity checks."
        """
        findings = []
        code = issue.code_sample

        # Pattern: comparison against writable file
        if re.search(r'open\(["\'].*expected|open\(["\'].*ref|open\(["\'].*hidden', code):
            if re.search(r'WRITABLE|writable|root|modify', code, re.IGNORECASE) or \
               re.search(r'agent.*root|runs.*root', issue.description, re.IGNORECASE):
                findings.append(Finding(
                    issue_id=issue.id,
                    vuln_class=VulnClass.WRITABLE_REFERENCE,
                    confidence=0.9,
                    reasoning="Test compares against file that agent can modify",
                    evidence=["reference file in agent-accessible path"],
                ))

        # Pattern: file comparison without integrity check
        if re.search(r'filecmp|diff|==.*expected', code) and \
           not re.search(r'hash|checksum|sha|md5|readonly|immutable', code):
            if 'WRITABLE' in code or 'writable' in code.lower():
                findings.append(Finding(
                    issue_id=issue.id,
                    vuln_class=VulnClass.WRITABLE_REFERENCE,
                    confidence=0.85,
                    reasoning="File comparison without integrity verification",
                    evidence=["no checksum or hash verification on reference file"],
                ))

        return findings

    def _scan_answer_leakage(self, issue: Issue) -> list[Finding]:
        """
        LLM prompt: "Are answers/solutions accessible in the evaluation environment?
        Look for: git history with future commits, solution files in workspace,
        issue descriptions containing fix instructions."
        """
        findings = []
        code = issue.code_sample
        desc = issue.description.lower()

        # Pattern: git clone without --single-branch
        if re.search(r'git.*clone', code) and '--single-branch' not in code:
            findings.append(Finding(
                issue_id=issue.id,
                vuln_class=VulnClass.ANSWER_LEAKAGE,
                confidence=0.9,
                reasoning="Full git clone exposes future commits with answers",
                evidence=["git clone without --single-branch"],
            ))

        # Pattern: no reflog cleanup
        if re.search(r'git.*clone|git.*reset', code) and 'reflog' not in code:
            if re.search(r'git.*remote.*remove', code):
                findings.append(Finding(
                    issue_id=issue.id,
                    vuln_class=VulnClass.ANSWER_LEAKAGE,
                    confidence=0.85,
                    reasoning="Remote removed but reflog/tags preserve future history",
                    evidence=["no reflog expire or tag cleanup"],
                ))

        # Pattern: answer files accessible
        if re.search(r'patch_files|resources/|solution.*visible|already.*present', code + " " + desc):
            findings.append(Finding(
                issue_id=issue.id,
                vuln_class=VulnClass.ANSWER_LEAKAGE,
                confidence=0.8,
                reasoning="Answer files accessible in the workspace",
                evidence=["solution data found in accessible paths"],
            ))

        # Pattern: solution in issue description
        if re.search(r'issue.*contain.*fix|fix.*in.*issue|leaks.*solution', desc):
            findings.append(Finding(
                issue_id=issue.id,
                vuln_class=VulnClass.ANSWER_LEAKAGE,
                confidence=0.85,
                reasoning="Issue description contains the solution code/instructions",
                evidence=["fix instructions embedded in task description"],
            ))

        return findings

    def _scan_spec_mismatch(self, issue: Issue) -> list[Finding]:
        """
        LLM prompt: "Do the tests align with the task description?
        Look for: tests that enforce undocumented requirements, tests that
        contradict documentation, tests that miss stated requirements."
        """
        findings = []
        code = issue.code_sample
        desc = issue.description.lower()

        # Pattern: contradiction
        if re.search(r'contradict|BUG.*contradict|inverted', code, re.IGNORECASE):
            findings.append(Finding(
                issue_id=issue.id,
                vuln_class=VulnClass.SPEC_MISMATCH,
                confidence=0.9,
                reasoning="Test assertion contradicts task documentation",
                evidence=["contradictory requirement detected"],
            ))

        # Pattern: undocumented requirements
        if re.search(r'undocumented|not.*mention|not.*in.*instruction', code, re.IGNORECASE):
            findings.append(Finding(
                issue_id=issue.id,
                vuln_class=VulnClass.SPEC_MISMATCH,
                confidence=0.8,
                reasoning="Tests enforce requirements not stated in task description",
                evidence=["undocumented requirements in assertions"],
            ))

        # Pattern: oracle solution has bug
        if re.search(r'oracle.*bug|oracle.*incorrect|BUG in oracle', code, re.IGNORECASE):
            findings.append(Finding(
                issue_id=issue.id,
                vuln_class=VulnClass.SPEC_MISMATCH,
                confidence=0.85,
                reasoning="Oracle/reference solution has a known bug",
                evidence=["buggy oracle solution"],
            ))

        # Pattern: exact string matching on formatted output
        if re.search(r'assert.*==.*".*\d{4}', code):  # dates, formatted strings
            findings.append(Finding(
                issue_id=issue.id,
                vuln_class=VulnClass.SPEC_MISMATCH,
                confidence=0.7,
                reasoning="Exact string matching on formatted output is fragile",
                evidence=["exact match on formatted string"],
            ))

        # Pattern: Python version mismatch
        if re.search(r'python.*version|Python\s*[23]\.\d', code + " " + desc):
            if re.search(r'mismatch|wrong|historical', desc):
                findings.append(Finding(
                    issue_id=issue.id,
                    vuln_class=VulnClass.SPEC_MISMATCH,
                    confidence=0.8,
                    reasoning="Test environment Python version doesn't match issue era",
                    evidence=["version mismatch"],
                ))

        # Pattern: PASS_TO_PASS failing
        if re.search(r'PASS_TO_PASS.*fail|classification.*error|fail.*before.*patch|fail.*before.*fix',
                      desc + " " + code, re.IGNORECASE):
            findings.append(Finding(
                issue_id=issue.id,
                vuln_class=VulnClass.SPEC_MISMATCH,
                confidence=0.75,
                reasoning="Tests classified as PASS_TO_PASS actually fail on base commit",
                evidence=["test classification error"],
            ))

        # Pattern: tool check without usage verification
        if re.search(r'which\s+\w+', code) and not re.search(r'session|pane|layout', code):
            if re.search(r'never.*check.*usage|BUG.*never.*check', code, re.IGNORECASE):
                findings.append(Finding(
                    issue_id=issue.id,
                    vuln_class=VulnClass.SPEC_MISMATCH,
                    confidence=0.8,
                    reasoning="Test checks tool installation but not usage",
                    evidence=["which command without usage verification"],
                ))

        return findings

    def _scan_infra_exploit(self, issue: Issue) -> list[Finding]:
        """
        LLM prompt: "Can evaluation infrastructure (Docker, CUDA, OS) be exploited?
        Look for: docker cp bugs, resource limits, environment mismatches."
        """
        findings = []
        code = issue.code_sample
        desc = issue.description.lower()

        # Pattern: docker cp without /.
        if re.search(r'docker.*cp|docker_cp', code, re.IGNORECASE) and \
           not re.search(r'/\.\s*["\']', code):
            findings.append(Finding(
                issue_id=issue.id,
                vuln_class=VulnClass.INFRA_EXPLOIT,
                confidence=0.85,
                reasoning="docker cp without /. suffix may nest directories",
                evidence=["docker cp missing /. on source path"],
            ))

        # Pattern: nproc / resource limit issues
        if re.search(r'nproc|make\s*-j', code):
            if re.search(r'host.*core|OOM|128', code + " " + desc):
                findings.append(Finding(
                    issue_id=issue.id,
                    vuln_class=VulnClass.INFRA_EXPLOIT,
                    confidence=0.8,
                    reasoning="nproc returns host core count inside container",
                    evidence=["nproc without cgroup limit"],
                ))

        # Pattern: external service dependency
        if re.search(r'httpbin|external.*service|503|network.*depend', code + " " + desc):
            findings.append(Finding(
                issue_id=issue.id,
                vuln_class=VulnClass.INFRA_EXPLOIT,
                confidence=0.75,
                reasoning="Tests depend on external services that may be unavailable",
                evidence=["external service dependency in evaluation"],
            ))

        # Pattern: input mutation
        if re.search(r'zero_\(\)|fill_\(\)|\.data\s*=', code):
            findings.append(Finding(
                issue_id=issue.id,
                vuln_class=VulnClass.INFRA_EXPLOIT,
                confidence=0.9,
                reasoning="In-place input mutation corrupts shared tensors",
                evidence=["in-place tensor mutation"],
            ))

        # Pattern: precision downgrade
        if re.search(r'\.half\(\)|\.bfloat16\(\)', code) and re.search(r'\.float\(\)', code):
            findings.append(Finding(
                issue_id=issue.id,
                vuln_class=VulnClass.INFRA_EXPLOIT,
                confidence=0.75,
                reasoning="Silent precision downgrade may pass tolerance checks",
                evidence=["precision cast pattern"],
            ))

        return findings

    def _scan_code_loopholes(self, issue: Issue) -> list[Finding]:
        """
        LLM prompt: "Can the agent submit code that trivially delegates to the
        reference implementation? Look for: PyTorch wrapper, inheritance, fallback."
        """
        findings = []
        code = issue.code_sample

        # Pattern: torch.nn usage in solution
        if re.search(r'torch\.nn\.\w+|nn\.\w+\(', code):
            if re.search(r'ModelNew|model_new|custom', code):
                findings.append(Finding(
                    issue_id=issue.id,
                    vuln_class=VulnClass.CODE_LOOPHOLE,
                    confidence=0.8,
                    reasoning="Solution uses PyTorch modules instead of custom kernel",
                    evidence=["torch.nn in ModelNew"],
                ))

        # Pattern: try-except fallback
        if re.search(r'try:.*except.*:', code, re.DOTALL):
            if re.search(r'torch\.nn|fallback|F\.\w+', code):
                findings.append(Finding(
                    issue_id=issue.id,
                    vuln_class=VulnClass.CODE_LOOPHOLE,
                    confidence=0.85,
                    reasoning="Try-except pattern with PyTorch fallback",
                    evidence=["try-except around kernel with PyTorch in except"],
                ))

        # Pattern: inheritance with no override
        if re.search(r'class\s+\w+\(Model\)', code) and re.search(r'pass\b', code):
            findings.append(Finding(
                issue_id=issue.id,
                vuln_class=VulnClass.CODE_LOOPHOLE,
                confidence=0.9,
                reasoning="Inherits from reference Model with no overrides",
                evidence=["class ModelNew(Model): pass"],
            ))

        return findings

    def _scan_eval_bugs(self, issue: Issue) -> list[Finding]:
        """
        LLM prompt: "Are there bugs in the evaluation/scoring scripts?
        Look for: index misalignment, parser errors, sync issues."
        """
        findings = []
        code = issue.code_sample
        desc = issue.description.lower()

        # Pattern: index-based pairing
        if re.search(r'results\[i\]|reference_times\[i\]', code):
            if re.search(r'order|missing|mismatch', code + " " + desc):
                findings.append(Finding(
                    issue_id=issue.id,
                    vuln_class=VulnClass.EVAL_SCRIPT_BUG,
                    confidence=0.8,
                    reasoning="Index-based result pairing breaks with missing/reordered data",
                    evidence=["index-based pairing without ID matching"],
                ))

        # Pattern: regex parser issues
        if re.search(r'regex|pattern.*format|parser', code + " " + desc):
            if re.search(r'BUG|bug|mismatch', code + " " + desc):
                findings.append(Finding(
                    issue_id=issue.id,
                    vuln_class=VulnClass.EVAL_SCRIPT_BUG,
                    confidence=0.75,
                    reasoning="Test result parser has format matching issues",
                    evidence=["parser regex mismatch"],
                ))

        # Pattern: unpinned dependencies
        if re.search(r'unpin|underspecif|conda.*spec', code + " " + desc):
            findings.append(Finding(
                issue_id=issue.id,
                vuln_class=VulnClass.EVAL_SCRIPT_BUG,
                confidence=0.8,
                reasoning="Unpinned dependency versions cause inconsistent evaluation",
                evidence=["underspecified package versions"],
            ))

        # Pattern: sync outside loop
        if re.search(r'synchronize.*outside|BUG.*sync', code + " " + desc):
            findings.append(Finding(
                issue_id=issue.id,
                vuln_class=VulnClass.EVAL_SCRIPT_BUG,
                confidence=0.7,
                reasoning="CUDA synchronization incorrectly placed",
                evidence=["sync outside warmup loop"],
            ))

        # Pattern: timing instability
        if re.search(r'instab|noise|coefficient.*variation|launch.*overhead', code + " " + desc):
            findings.append(Finding(
                issue_id=issue.id,
                vuln_class=VulnClass.EVAL_SCRIPT_BUG,
                confidence=0.65,
                reasoning="Timing measurements are numerically unstable for small kernels",
                evidence=["timing noise dominates measurement"],
            ))

        return findings

    def _scan_statistical_exploits(self, issue: Issue) -> list[Finding]:
        """
        LLM prompt: "Can statistical properties of the input distribution be
        exploited? Look for: uniform distributions with reduction ops, Law of
        Large Numbers convergence, closed-form expected values."
        """
        findings = []
        code = issue.code_sample

        # Pattern: uniform distribution + reduction to scalar
        if re.search(r'torch\.rand\b', code) and re.search(r'torch\.mean|\.mean\(', code):
            findings.append(Finding(
                issue_id=issue.id,
                vuln_class=VulnClass.STATISTICAL_EXPLOIT,
                confidence=0.85,
                reasoning="Uniform distribution + mean reduction enables LLN convergence exploit",
                evidence=["torch.rand input", "reduction to scalar"],
            ))

        # Pattern: closed-form analytical solution
        if re.search(r'analytic|closed.form|expected.*value', code + " " + issue.description, re.IGNORECASE):
            findings.append(Finding(
                issue_id=issue.id,
                vuln_class=VulnClass.STATISTICAL_EXPLOIT,
                confidence=0.8,
                reasoning="Loss function has closed-form expected value for given distribution",
                evidence=["analytical solution possible"],
            ))

        # Pattern: HuberLoss with delta >= input range
        if re.search(r'HuberLoss|huber', code, re.IGNORECASE) and re.search(r'torch\.rand', code):
            findings.append(Finding(
                issue_id=issue.id,
                vuln_class=VulnClass.STATISTICAL_EXPLOIT,
                confidence=0.85,
                reasoning="Huber loss collapses to MSE when delta >= max |prediction - target|",
                evidence=["HuberLoss with uniform inputs within delta range"],
            ))

        # Pattern: binary targets with uniform predictions
        if re.search(r'randint.*0.*2|targets.*\{-1.*\+1\}|\*\s*2\s*-\s*1', code):
            findings.append(Finding(
                issue_id=issue.id,
                vuln_class=VulnClass.STATISTICAL_EXPLOIT,
                confidence=0.8,
                reasoning="Binary targets with uniform predictions have analytical expected loss",
                evidence=["binary target distribution"],
            ))

        return findings

    def _scan_timing_exploits(self, issue: Issue) -> list[Finding]:
        """
        LLM prompt: "Can timing measurements be manipulated?
        Look for: CUDA stream manipulation, async computation, deferred evaluation."
        """
        findings = []
        code = issue.code_sample

        # Pattern: non-default CUDA stream
        if re.search(r'torch\.cuda\.Stream|cuda\.stream\(', code):
            findings.append(Finding(
                issue_id=issue.id,
                vuln_class=VulnClass.TIMING_EXPLOIT,
                confidence=0.95,
                reasoning="Computation on non-default stream escapes timing measurement",
                evidence=["torch.cuda.Stream creation"],
            ))

        # Pattern: threading in forward pass
        if re.search(r'threading\.Thread|Thread\(target', code):
            findings.append(Finding(
                issue_id=issue.id,
                vuln_class=VulnClass.TIMING_EXPLOIT,
                confidence=0.9,
                reasoning="Background thread performs computation while timing measures main thread",
                evidence=["threading.Thread in forward pass"],
            ))

        # Pattern: lazy tensor / deferred computation
        if re.search(r'__eq__|__new__|Tensor.*subclass|_make_subclass', code):
            findings.append(Finding(
                issue_id=issue.id,
                vuln_class=VulnClass.TIMING_EXPLOIT,
                confidence=0.9,
                reasoning="Lazy tensor defers computation to comparison operators",
                evidence=["Tensor subclass with deferred computation"],
            ))

        return findings

    def _scan_memory_exploits(self, issue: Issue) -> list[Finding]:
        """
        LLM prompt: "Can CUDA memory allocation behavior be exploited?
        Look for: torch.empty without initialization, memory reuse patterns."
        """
        findings = []
        code = issue.code_sample

        # Pattern: torch.empty in forward (no init)
        if re.search(r'torch\.empty\(', code) and re.search(r'forward|ModelNew', code):
            if 'reuse' in code.lower() or 'cache' in code.lower() or 'stale' in code.lower():
                findings.append(Finding(
                    issue_id=issue.id,
                    vuln_class=VulnClass.MEMORY_EXPLOIT,
                    confidence=0.9,
                    reasoning="torch.empty may return CUDA cached memory with reference values",
                    evidence=["torch.empty in forward pass"],
                ))

        return findings

    def _scan_env_exploits(self, issue: Issue) -> list[Finding]:
        """
        LLM prompt: "Can the agent manipulate the evaluation environment?
        Look for: monkey-patching, stack inspection, function overwriting."
        """
        findings = []
        code = issue.code_sample

        # Pattern: inspect.stack
        if re.search(r'inspect\.stack|f_locals|frame_info', code):
            findings.append(Finding(
                issue_id=issue.id,
                vuln_class=VulnClass.ENV_EXPLOIT,
                confidence=0.95,
                reasoning="Stack frame inspection to find grader's reference tensor",
                evidence=["inspect.stack() + f_locals access"],
            ))

        # Pattern: monkey-patching
        if re.search(r'torch\.cuda\.synchronize\s*=|time\.time\s*=|time\.perf_counter\s*=', code):
            findings.append(Finding(
                issue_id=issue.id,
                vuln_class=VulnClass.ENV_EXPLOIT,
                confidence=0.95,
                reasoning="Monkey-patching timing/sync functions to corrupt measurements",
                evidence=["function overwriting detected"],
            ))

        return findings

    def _scan_data_contamination(self, issue: Issue) -> list[Finding]:
        findings = []
        desc = issue.description.lower()
        if re.search(r'contamination|memoriz|training data', desc):
            findings.append(Finding(
                issue_id=issue.id,
                vuln_class=VulnClass.DATA_CONTAMINATION,
                confidence=0.8,
                reasoning="Benchmark uses popular repos likely in LLM training data",
                evidence=["popular open-source repositories in benchmark"],
            ))
        return findings

    def _scan_missing_deps(self, issue: Issue) -> list[Finding]:
        findings = []
        code = issue.code_sample
        if re.search(r'Missing.*procps|missing.*package|apt.*install', code, re.IGNORECASE):
            if re.search(r'crash|ENOENT|unsolvable', code + " " + issue.description, re.IGNORECASE):
                findings.append(Finding(
                    issue_id=issue.id,
                    vuln_class=VulnClass.MISSING_DEPENDENCY,
                    confidence=0.85,
                    reasoning="Missing system package causes task to be unsolvable",
                    evidence=["missing dependency in Dockerfile"],
                ))
        return findings

    def _scan_safety(self, issue: Issue) -> list[Finding]:
        findings = []
        desc = issue.description.lower() + " " + issue.code_sample.lower()
        if re.search(r'tor\b|circumvent|proxy|socks5|bypass', desc):
            findings.append(Finding(
                issue_id=issue.id,
                vuln_class=VulnClass.SAFETY_CONCERN,
                confidence=0.9,
                reasoning="Agent installs circumvention tools without human oversight",
                evidence=["network circumvention technology"],
            ))
        return findings

    def _cross_reference_analysis(self, issue: Issue) -> list[Finding]:
        """
        LLM Pass 2: Holistic reasoning across multiple signals.
        Catches vulnerabilities that require understanding relationships
        between code elements.
        """
        findings = []
        code = issue.code_sample
        desc = issue.description.lower()

        # Cross-reference: test only checks existence + answer is predictable
        has_existence_check = bool(re.search(r'os\.path\.(exists|isdir)', code))
        has_hardcoded_value = bool(re.search(r'==\s*[\d.]+|HARDCODED', code))
        if has_existence_check and has_hardcoded_value:
            findings.append(Finding(
                issue_id=issue.id,
                vuln_class=VulnClass.WEAK_TEST,
                confidence=0.9,
                reasoning="Combination: existence check + predictable value = trivially hackable",
                evidence=["multiple weak test patterns compound"],
            ))

        # Cross-reference: git operations without full cleanup chain
        git_ops = {
            'clone': bool(re.search(r'git.*clone', code)),
            'reset': bool(re.search(r'git.*reset', code)),
            'remote_remove': bool(re.search(r'remote.*remove', code)),
            'tag_cleanup': bool(re.search(r'tag.*-d|tag.*delete', code)),
            'reflog_expire': bool(re.search(r'reflog.*expire', code)),
            'gc_prune': bool(re.search(r'gc.*prune', code)),
        }
        if git_ops['clone'] and git_ops['reset'] and not git_ops['gc_prune']:
            findings.append(Finding(
                issue_id=issue.id,
                vuln_class=VulnClass.ANSWER_LEAKAGE,
                confidence=0.9,
                reasoning="Git cleanup chain incomplete: clone+reset without gc/prune",
                evidence=[f"missing: {[k for k,v in git_ops.items() if not v]}"],
            ))

        return findings


# ============================================================================
# Runner
# ============================================================================

def run_llm_detection(issues: list[Issue] = None) -> dict[str, DetectionResult]:
    """Run LLM detector on all issues and return results."""
    if issues is None:
        issues = ALL_ISSUES

    detector = LLMDetector()
    results = {}
    for issue in issues:
        results[issue.id] = detector.analyze(issue)
    return results


if __name__ == "__main__":
    results = run_llm_detection()
    detected = sum(1 for r in results.values() if r.detected)
    print(f"LLM Detector: {detected}/{len(results)} issues detected")
    print()
    for issue_id, result in results.items():
        status = "DETECTED" if result.detected else "MISSED"
        classes = [f.vuln_class.value for f in result.findings]
        print(f"  {issue_id}: {status} {classes}")
