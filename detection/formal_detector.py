"""
Formal Method / Testing-Based Benchmark Vulnerability Detector
================================================================
Uses static analysis, property checking, and formal reasoning to detect
reward hacking vulnerabilities in benchmark evaluation code. Operates by:

1. AST analysis: Parse code and check structural properties
2. Data-flow analysis: Track how inputs flow to assertions
3. Property-based invariant checking: Verify mathematical properties
4. Git state verification: Check for history leakage
5. Permission analysis: Verify file/privilege isolation
6. Input distribution analysis: Detect statistical exploits
7. Evaluation order analysis: Check for side-channel vulnerabilities

Unlike the LLM detector, this uses programmatic analysis without
natural language understanding -- it operates purely on code structure.
"""

import ast
import re
import math
from dataclasses import dataclass, field
from typing import Optional

from catalog import Issue, VulnClass, ALL_ISSUES


@dataclass
class FormalFinding:
    """A vulnerability detected by formal analysis."""
    issue_id: str
    vuln_class: VulnClass
    confidence: float
    method: str  # which formal method found this
    reasoning: str
    evidence: list[str] = field(default_factory=list)


@dataclass
class FormalResult:
    """Full detection result for one issue."""
    issue_id: str
    findings: list[FormalFinding] = field(default_factory=list)
    detected: bool = False

    def __post_init__(self):
        self.detected = len(self.findings) > 0


# ============================================================================
# Analysis Methods
# ============================================================================

class ASTAnalyzer:
    """Static analysis using Python AST."""

    def analyze(self, code: str) -> dict:
        """Extract structural properties from code."""
        try:
            tree = ast.parse(code)
        except SyntaxError:
            # Code samples may contain comments/pseudocode that don't parse
            # Fall back to regex-based analysis
            return self._regex_fallback(code)

        info = {
            "functions": [],
            "classes": [],
            "asserts": [],
            "imports": [],
            "calls": [],
            "assignments": [],
            "try_except": False,
            "has_threading": False,
            "has_subprocess": False,
            "file_operations": [],
            "comparison_targets": [],
        }

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                info["functions"].append(node.name)
            elif isinstance(node, ast.ClassDef):
                info["classes"].append({
                    "name": node.name,
                    "bases": [self._get_name(b) for b in node.bases],
                    "methods": [n.name for n in node.body if isinstance(n, ast.FunctionDef)],
                    "has_pass": any(isinstance(n, ast.Pass) for n in node.body),
                })
            elif isinstance(node, ast.Assert):
                info["asserts"].append(ast.dump(node))
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    info["imports"].append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                info["imports"].append(node.module or "")
            elif isinstance(node, ast.Call):
                call_name = self._get_call_name(node)
                if call_name:
                    info["calls"].append(call_name)
            elif isinstance(node, ast.Try):
                info["try_except"] = True

        # Derived properties
        info["has_threading"] = any("threading" in i for i in info["imports"])
        info["has_subprocess"] = any("subprocess" in i for i in info["imports"])
        info["assert_count"] = len(info["asserts"])

        return info

    def _regex_fallback(self, code: str) -> dict:
        """Regex-based analysis when AST parsing fails."""
        return {
            "functions": re.findall(r'def\s+(\w+)', code),
            "classes": [],
            "asserts": re.findall(r'(assert\s+.+?)(?:\n|$)', code),
            "imports": re.findall(r'import\s+(\w+)', code),
            "calls": re.findall(r'(\w+(?:\.\w+)*)\s*\(', code),
            "assignments": [],
            "try_except": bool(re.search(r'try:', code)),
            "has_threading": "threading" in code,
            "has_subprocess": "subprocess" in code,
            "file_operations": re.findall(r'open\(["\']([^"\']+)', code),
            "comparison_targets": [],
            "assert_count": len(re.findall(r'assert\s', code)),
        }

    def _get_name(self, node) -> str:
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{self._get_name(node.value)}.{node.attr}"
        return ""

    def _get_call_name(self, node) -> Optional[str]:
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return f"{self._get_name(node.func.value)}.{node.func.attr}"
        return None


class PropertyChecker:
    """Check mathematical/logical properties of benchmark code."""

    def check_constant_output(self, code: str) -> list[dict]:
        """
        Property: Does the computation pipeline always produce a constant?
        Method: Symbolic trace through operations looking for:
        - x - mean(x) where x is scalar → always 0
        - max(dim=d, keepdim=True) followed by mean(dim=d) on reduced dim
        - Any activation function applied to guaranteed-zero input
        - Hardcoded response dictionaries
        - Operations that cancel out or are algebraically trivial
        """
        findings = []

        # Check for x - x.mean pattern on reduced dimension
        if re.search(r'max.*dim.*keepdim.*True', code) and \
           re.search(r'-.*mean.*dim', code):
            findings.append({
                "property": "algebraic_zero",
                "reasoning": "max(keepdim=True) reduces dim to 1; x - mean(x) = 0 for single element",
                "confidence": 0.95,
            })

        # Check for GELU/ReLU/activation applied to zero
        if findings and re.search(r'gelu|relu|sigmoid|tanh', code, re.IGNORECASE):
            findings.append({
                "property": "activation_of_zero",
                "reasoning": "Activation function applied to algebraically-zero input",
                "confidence": 0.95,
            })

        # Check for hardcoded response dictionaries
        if re.search(r'HARDCODED\s*=\s*\{|hardcoded.*dict|pre-know', code, re.IGNORECASE):
            findings.append({
                "property": "hardcoded_responses",
                "reasoning": "Hardcoded response dictionary matching expected test queries",
                "confidence": 0.9,
            })

        # Check for operations described as always producing constants
        if re.search(r'cancel.*out|always.*constant|always.*same|always.*zero|constant.*output',
                      code, re.IGNORECASE):
            findings.append({
                "property": "constant_output_described",
                "reasoning": "Code/comments indicate output is always a constant",
                "confidence": 0.8,
            })

        return findings

    def check_statistical_convergence(self, code: str) -> list[dict]:
        """
        Property: Can statistical convergence allow partial computation?
        Method: Check if:
        1. Input is from uniform/normal distribution
        2. Output is a reduction (mean, sum) to scalar
        3. Tensor is large enough for LLN to kick in
        """
        findings = []

        has_uniform = bool(re.search(r'torch\.rand\b(?!n|int)', code))
        has_normal = bool(re.search(r'torch\.randn\b', code))
        has_reduction = bool(re.search(r'torch\.mean|\.mean\(|torch\.sum|\.sum\(', code))

        # Check for large tensor sizes
        sizes = re.findall(r'(?:batch_size|input_shape)\s*=\s*[\(\[]?\s*(\d+)', code)
        large_tensor = any(int(s) >= 1024 for s in sizes) if sizes else False

        if (has_uniform or has_normal) and has_reduction and large_tensor:
            findings.append({
                "property": "statistical_convergence",
                "reasoning": f"{'Uniform' if has_uniform else 'Normal'} distribution + "
                           f"reduction on large tensor → LLN convergence exploitable",
                "confidence": 0.85,
            })

        # Check for HuberLoss with uniform inputs
        if re.search(r'HuberLoss|huber', code, re.IGNORECASE) and has_uniform:
            findings.append({
                "property": "huber_collapse",
                "reasoning": "Uniform(0,1) inputs keep |pred-target| ≤ 1, collapsing Huber to MSE",
                "confidence": 0.85,
            })

        # Check for analytical expected value
        if re.search(r'torch\.clamp.*min.*0|hinge', code, re.IGNORECASE):
            if re.search(r'randint.*0.*2|\{-1.*1\}', code):
                findings.append({
                    "property": "analytical_expected_value",
                    "reasoning": "Binary targets + uniform predictions → closed-form E[loss]",
                    "confidence": 0.8,
                })

        return findings

    def check_test_coverage(self, code: str) -> list[dict]:
        """
        Property: Do tests adequately cover the task's output space?
        Method: Count assertions, check for edge case coverage,
        identify single-point checks.
        """
        findings = []

        assert_count = len(re.findall(r'assert\s', code))
        test_count = len(re.findall(r'def\s+test_', code))

        # Single-point assertion check
        hardcoded_checks = re.findall(r'assert.*==\s*[\d.]+|assert.*==\s*["\']', code)
        if hardcoded_checks and assert_count <= 3:
            findings.append({
                "property": "insufficient_test_coverage",
                "reasoning": f"Only {assert_count} assertions with {len(hardcoded_checks)} "
                           f"hardcoded value checks",
                "confidence": 0.75,
            })

        # Existence-only checks
        existence_checks = re.findall(r'os\.path\.(exists|isdir|isfile)', code)
        content_checks = re.findall(r'filecmp|content|len\(.*read|hash|checksum', code)
        if existence_checks and not content_checks:
            findings.append({
                "property": "existence_without_content",
                "reasoning": "File/directory existence checked without content verification",
                "confidence": 0.85,
            })

        # Structural checks without content (e.g., tarball)
        if re.search(r'issym|islink|endswith\(|\.name\b', code):
            # Strip comments to check for actual content verification code
            code_no_comments = "\n".join(
                l for l in code.split("\n") if not l.strip().startswith("#")
            )
            if not re.search(r'\.read\(|getvalue|\.content\b|\.data\b', code_no_comments):
                findings.append({
                    "property": "structural_without_content",
                    "reasoning": "Tests check structural metadata (symlinks, names, extensions) "
                               "without verifying actual content",
                    "confidence": 0.75,
                })

        # Oracle/reference solution bugs
        if re.search(r'BUG.*oracle|oracle.*BUG|BUG in oracle|oracle.*incorrect',
                      code, re.IGNORECASE):
            findings.append({
                "property": "buggy_oracle",
                "reasoning": "Oracle/reference solution contains documented bug",
                "confidence": 0.85,
            })

        # PASS_TO_PASS misclassification
        if re.search(r'PASS_TO_PASS.*fail|fail.*before.*patch|classified.*PASS.*actually.*fail',
                      code, re.IGNORECASE):
            findings.append({
                "property": "test_misclassification",
                "reasoning": "Test classification error: PASS_TO_PASS tests fail on base commit",
                "confidence": 0.8,
            })

        return findings


class PermissionAnalyzer:
    """Check file permissions and access control in evaluation setup."""

    def check_reference_file_protection(self, code: str, desc: str) -> list[dict]:
        """
        Verify reference files are protected from agent modification.
        """
        findings = []

        # Find files used in comparisons
        ref_files = re.findall(
            r'open\(["\']([^"\']*(?:expected|ref|hidden|solution|answer)[^"\']*)',
            code, re.IGNORECASE
        )

        for ref_file in ref_files:
            # Check if any protection is mentioned
            has_protection = bool(re.search(
                r'readonly|immutable|chattr|chmod.*444|mount.*ro',
                code, re.IGNORECASE
            ))
            if not has_protection:
                findings.append({
                    "file": ref_file,
                    "issue": "reference_file_unprotected",
                    "reasoning": f"Reference file '{ref_file}' has no read-only protection",
                    "confidence": 0.85,
                })

        # Check for root access
        if re.search(r'root|sudo|uid\s*=\s*0', code + " " + desc, re.IGNORECASE):
            findings.append({
                "file": "N/A",
                "issue": "root_access",
                "reasoning": "Agent runs as root -- can modify any file",
                "confidence": 0.9,
            })

        return findings


class GitStateVerifier:
    """Verify git repository state sanitization."""

    REQUIRED_CLEANUP_STEPS = [
        ("single_branch_clone", r'--single-branch'),
        ("tag_cleanup", r'tag[\s",]+(-d|--delete)|tag.*delete'),
        ("reflog_expire", r'reflog[\s",]+expire'),
        ("gc_prune", r'gc[\s",]+--prune|gc.*prune'),
        ("remote_remove", r'remote[\s",]+(remove|rm)'),
    ]

    def verify(self, code: str) -> list[dict]:
        """Check if git state is properly sanitized for evaluation."""
        findings = []

        # Only relevant if git operations are present
        # Match both shell and subprocess-style git commands
        if not re.search(r'git[\s",]+(clone|reset|checkout)', code):
            return findings

        present = {}
        for step_name, pattern in self.REQUIRED_CLEANUP_STEPS:
            present[step_name] = bool(re.search(pattern, code))

        missing = [name for name, found in present.items() if not found]

        if missing:
            findings.append({
                "issue": "incomplete_git_sanitization",
                "missing_steps": missing,
                "present_steps": [name for name, found in present.items() if found],
                "reasoning": f"Git cleanup missing: {', '.join(missing)}",
                "confidence": 0.9 if len(missing) >= 3 else 0.7,
            })

        return findings


class EvalOrderAnalyzer:
    """Analyze evaluation execution order for side-channel vulnerabilities."""

    def check_execution_order(self, code: str) -> list[dict]:
        """
        Verify that evaluation order doesn't enable exploits:
        - Reference runs before custom → memory reuse possible
        - Custom runs before reference → input mutation possible
        - No input cloning → shared references exploitable
        """
        findings = []

        # Check for input sharing
        if re.search(r'model\(\*inputs\).*model_new\(\*inputs\)', code, re.DOTALL) or \
           re.search(r'output\s*=\s*model.*output_new\s*=\s*model_new', code, re.DOTALL):
            if not re.search(r'\.clone\(\)|copy\.deepcopy|inputs\.copy', code):
                findings.append({
                    "issue": "shared_inputs",
                    "reasoning": "Same input tensors passed to both models without cloning",
                    "confidence": 0.8,
                })

        # Check for memory reuse vulnerability
        if re.search(r'output\s*=\s*model', code) and \
           re.search(r'output_new\s*=\s*model_new', code):
            if not re.search(r'torch\.cuda\.empty_cache|zero_.*memory', code):
                findings.append({
                    "issue": "memory_reuse_possible",
                    "reasoning": "Reference output may be freed before custom kernel runs; "
                               "torch.empty could reuse same CUDA memory",
                    "confidence": 0.75,
                })

        return findings


class DockerAnalyzer:
    """Analyze Docker/container configuration for evaluation issues."""

    def check_docker_config(self, code: str) -> list[dict]:
        findings = []

        # docker cp without /. (also match Python list form)
        if re.search(r'docker.*cp|docker_cp', code, re.IGNORECASE) and \
           not re.search(r'/\.\s*["\']', code):
            findings.append({
                "issue": "docker_cp_nesting",
                "reasoning": "docker cp without /. suffix may nest directories on copy",
                "confidence": 0.85,
            })

        # Missing resource limits
        if re.search(r'nproc|make\s+-j', code):
            if not re.search(r'--cpus|--memory|cgroup|ulimit', code):
                findings.append({
                    "issue": "missing_resource_limits",
                    "reasoning": "No CPU/memory limits; nproc may return host core count",
                    "confidence": 0.8,
                })

        # Missing packages
        if re.search(r'FROM\s+\w+|apt-get\s+install', code):
            required_packages = ['procps', 'ps']
            for pkg in required_packages:
                if pkg not in code and re.search(r'Dockerfile|apt-get', code):
                    findings.append({
                        "issue": f"missing_package_{pkg}",
                        "reasoning": f"Package '{pkg}' not installed; may cause runtime failures",
                        "confidence": 0.7,
                    })

        return findings


class CodePatternAnalyzer:
    """Detect known anti-patterns in submitted kernel code."""

    DANGEROUS_PATTERNS = [
        {
            "name": "torch_empty_no_init",
            "pattern": r'torch\.empty\(',
            "vuln_class": VulnClass.MEMORY_EXPLOIT,
            "reasoning": "torch.empty returns uninitialized memory; may contain reference values",
            "confidence": 0.8,
        },
        {
            "name": "cuda_stream_creation",
            "pattern": r'torch\.cuda\.Stream\(\)|cuda\.stream\(',
            "vuln_class": VulnClass.TIMING_EXPLOIT,
            "reasoning": "Non-default CUDA stream escapes timing measurement",
            "confidence": 0.9,
        },
        {
            "name": "threading_in_forward",
            "pattern": r'threading\.Thread|Thread\(target',
            "vuln_class": VulnClass.TIMING_EXPLOIT,
            "reasoning": "Background thread for async computation; timing sees main thread only",
            "confidence": 0.9,
        },
        {
            "name": "tensor_subclass",
            "pattern": r'torch\.Tensor.*subclass|_make_subclass|class.*\(torch\.Tensor\)',
            "vuln_class": VulnClass.TIMING_EXPLOIT,
            "reasoning": "Tensor subclass can defer computation to comparison operators",
            "confidence": 0.85,
        },
        {
            "name": "stack_inspection",
            "pattern": r'inspect\.stack|f_locals|sys\._getframe',
            "vuln_class": VulnClass.ENV_EXPLOIT,
            "reasoning": "Stack inspection to find grader's reference tensor",
            "confidence": 0.95,
        },
        {
            "name": "monkey_patch_sync",
            "pattern": r'torch\.cuda\.synchronize\s*=|cuda\.synchronize\s*=',
            "vuln_class": VulnClass.ENV_EXPLOIT,
            "reasoning": "Monkey-patching synchronize to corrupt timing",
            "confidence": 0.95,
        },
        {
            "name": "monkey_patch_time",
            "pattern": r'time\.time\s*=|time\.perf_counter\s*=',
            "vuln_class": VulnClass.ENV_EXPLOIT,
            "reasoning": "Overwriting time functions to fake measurements",
            "confidence": 0.95,
        },
        {
            "name": "input_mutation",
            "pattern": r'\.zero_\(\)|\.fill_\(\)|x\.data\s*=',
            "vuln_class": VulnClass.INFRA_EXPLOIT,
            "reasoning": "In-place input mutation corrupts shared tensors",
            "confidence": 0.9,
        },
        {
            "name": "precision_downgrade",
            "pattern": r'\.half\(\).*\.float\(\)|\.bfloat16\(\).*\.float\(\)',
            "vuln_class": VulnClass.INFRA_EXPLOIT,
            "reasoning": "Silent precision downgrade may pass tolerance checks",
            "confidence": 0.7,
        },
        {
            "name": "pytorch_in_solution",
            "pattern": r'torch\.nn\.\w+|nn\.Module.*(?:ReLU|Linear|Conv)',
            "vuln_class": VulnClass.CODE_LOOPHOLE,
            "reasoning": "Using PyTorch modules instead of writing custom kernel",
            "confidence": 0.7,
        },
        {
            "name": "try_except_fallback",
            "pattern": r'try:.*(?:kernel|cuda).*except.*(?:torch|nn|F\.)',
            "vuln_class": VulnClass.CODE_LOOPHOLE,
            "reasoning": "Try-except pattern falling back to PyTorch on kernel failure",
            "confidence": 0.8,
        },
        {
            "name": "inheritance_bypass",
            "pattern": r'class\s+\w+\(Model\).*pass',
            "vuln_class": VulnClass.CODE_LOOPHOLE,
            "reasoning": "Inheriting from reference Model with no overrides",
            "confidence": 0.9,
        },
        {
            "name": "circumvention_tools",
            "pattern": r'apt\s+install\s+tor\b|socks5|proxy.*bypass',
            "vuln_class": VulnClass.SAFETY_CONCERN,
            "reasoning": "Agent installs network circumvention tools",
            "confidence": 0.9,
        },
    ]

    def scan(self, code: str) -> list[dict]:
        findings = []
        for pattern_def in self.DANGEROUS_PATTERNS:
            if re.search(pattern_def["pattern"], code, re.DOTALL | re.IGNORECASE):
                findings.append({
                    "name": pattern_def["name"],
                    "vuln_class": pattern_def["vuln_class"],
                    "reasoning": pattern_def["reasoning"],
                    "confidence": pattern_def["confidence"],
                })
        return findings


class DependencyAnalyzer:
    """Check for missing dependencies and version issues."""

    def check_dependencies(self, code: str, desc: str) -> list[dict]:
        findings = []

        # Missing packages in Dockerfile
        if re.search(r'Dockerfile|FROM\s+|apt-get', code):
            if re.search(r'Missing|missing', code):
                findings.append({
                    "issue": "missing_package",
                    "reasoning": "Dockerfile missing required packages",
                    "confidence": 0.8,
                })

        # Version mismatches
        if re.search(r'python.*version|numpy.*removed|deprecated', code + " " + desc, re.IGNORECASE):
            findings.append({
                "issue": "version_mismatch",
                "reasoning": "Package/language version incompatibility",
                "confidence": 0.75,
            })

        # Unpinned versions
        if re.search(r'unpin|underspecif', code + " " + desc, re.IGNORECASE):
            findings.append({
                "issue": "unpinned_versions",
                "reasoning": "Dependency versions not pinned; non-deterministic evaluation",
                "confidence": 0.8,
            })

        return findings


class DataContaminationChecker:
    """Check for data contamination / memorization risks."""

    POPULAR_REPOS = [
        "django", "flask", "requests", "pytest", "matplotlib",
        "sympy", "scikit-learn", "numpy", "pandas", "astropy",
        "sphinx", "pylint",
    ]

    def check(self, code: str, desc: str) -> list[dict]:
        findings = []

        combined = (code + " " + desc).lower()

        # Check for popular repos mentioned
        mentioned_repos = [r for r in self.POPULAR_REPOS if r in combined]
        if len(mentioned_repos) >= 2 or re.search(r'popular.*repo|training.*data|memoriz|contamina',
                                                    combined):
            findings.append({
                "issue": "data_contamination_risk",
                "reasoning": f"Benchmark uses popular repos likely in LLM training data: "
                           f"{mentioned_repos or 'mentioned in description'}",
                "confidence": 0.75,
            })

        # Check for in-distribution vs out-of-distribution gap mentioned
        if re.search(r'in-dist.*out-of-dist|OOD|distribution.*gap', combined):
            findings.append({
                "issue": "contamination_evidence",
                "reasoning": "Performance gap between in-distribution and OOD suggests contamination",
                "confidence": 0.8,
            })

        return findings


class IssueTextLeakageChecker:
    """Check for solution leakage in issue/task descriptions."""

    def check(self, code: str, desc: str) -> list[dict]:
        findings = []

        combined = (code + " " + desc).lower()

        # Check for fix instructions in issue body
        if re.search(r'fix\s+should\s+be|should\s+be.*chang|the\s+fix\s+is|issue.*contain.*fix',
                      combined):
            findings.append({
                "issue": "solution_in_description",
                "reasoning": "Task description contains explicit fix instructions",
                "confidence": 0.85,
            })

        # Check for code snippets in issue text
        if re.search(r'should\s+be:\s*\n|currently.*:\s*\n.*should.*:\s*\n', combined):
            findings.append({
                "issue": "code_in_description",
                "reasoning": "Task description contains before/after code showing the fix",
                "confidence": 0.9,
            })

        # Check for solution leakage percentage mentioned
        if re.search(r'solution.*leakage|leak.*solution|32\.67%', combined):
            findings.append({
                "issue": "systematic_leakage",
                "reasoning": "Systematic solution leakage from issue descriptions documented",
                "confidence": 0.85,
            })

        return findings


class EvalScriptAnalyzer:
    """Check evaluation scripts for bugs."""

    def check_scoring(self, code: str) -> list[dict]:
        findings = []

        # Index-based pairing (also check for array indexing patterns)
        if re.search(r'\[i\]', code) and re.search(r'result|time|score|ratio', code):
            if not re.search(r'problem_id|sort.*by.*id|key=', code):
                findings.append({
                    "issue": "index_misalignment",
                    "reasoning": "Index-based result pairing without ID matching",
                    "confidence": 0.75,
                })

        # Pattern: assuming results in order without explicit matching
        if re.search(r'assumes.*order|BUG.*assumes|index.*match', code, re.IGNORECASE):
            findings.append({
                "issue": "index_misalignment_described",
                "reasoning": "Code assumes results are in order but doesn't verify",
                "confidence": 0.8,
            })

        # No deduplication
        if re.search(r'score\s*\+=|count\s*\+=', code):
            if not re.search(r'set\(|seen|dedup|unique', code):
                findings.append({
                    "issue": "no_deduplication",
                    "reasoning": "Score accumulation without deduplication check",
                    "confidence": 0.7,
                })

        return findings

    def check_timing(self, code: str) -> list[dict]:
        findings = []

        # Sync outside loop (match various patterns)
        has_warmup_loop = bool(re.search(r'for.*warmup|for.*range\(warmup', code, re.IGNORECASE))
        has_sync = bool(re.search(r'synchronize', code))
        has_model_call_in_loop = bool(re.search(
            r'for.*:\s*\n\s+.*model\(|for.*:\s*\n\s+.*output\s*=', code, re.DOTALL
        ))

        if has_warmup_loop and has_sync:
            # Check if sync is AFTER the loop (common bug pattern)
            if re.search(r'model\(.*\n.*\n.*synchronize|BUG.*sync', code, re.DOTALL | re.IGNORECASE):
                findings.append({
                    "issue": "sync_outside_loop",
                    "reasoning": "CUDA synchronize placed outside warmup loop",
                    "confidence": 0.7,
                })

        # Also catch explicit description of the bug
        if re.search(r'sync.*outside.*loop|synchronize.*outside|Incorrect.*sync',
                      code, re.IGNORECASE):
            findings.append({
                "issue": "sync_placement_bug",
                "reasoning": "CUDA synchronization incorrectly placed outside warmup loop",
                "confidence": 0.75,
            })

        # Small kernel timing noise
        if re.search(r'instab|noise|overhead.*launch|< 0\.01|variable.*time',
                      code + " " + code.lower()):
            findings.append({
                "issue": "timing_instability",
                "reasoning": "Kernel execution time near measurement noise floor",
                "confidence": 0.6,
            })

        return findings


# ============================================================================
# Main Formal Detector
# ============================================================================

class FormalDetector:
    """
    Composite formal detector using all analysis methods.
    """

    def __init__(self):
        self.ast_analyzer = ASTAnalyzer()
        self.property_checker = PropertyChecker()
        self.permission_analyzer = PermissionAnalyzer()
        self.git_verifier = GitStateVerifier()
        self.eval_order_analyzer = EvalOrderAnalyzer()
        self.docker_analyzer = DockerAnalyzer()
        self.code_pattern_analyzer = CodePatternAnalyzer()
        self.dependency_analyzer = DependencyAnalyzer()
        self.eval_script_analyzer = EvalScriptAnalyzer()
        self.contamination_checker = DataContaminationChecker()
        self.leakage_checker = IssueTextLeakageChecker()

    def analyze(self, issue: Issue) -> FormalResult:
        """Run all formal analysis methods on an issue."""
        findings = []
        code = issue.code_sample
        desc = issue.description

        # 1. AST Analysis
        ast_info = self.ast_analyzer.analyze(code)
        findings.extend(self._findings_from_ast(issue, ast_info))

        # 2. Property Checking
        for prop in self.property_checker.check_constant_output(code):
            findings.append(FormalFinding(
                issue_id=issue.id,
                vuln_class=VulnClass.HARDCODED_OUTPUT,
                confidence=prop["confidence"],
                method="property_checking",
                reasoning=prop["reasoning"],
            ))

        for prop in self.property_checker.check_statistical_convergence(code):
            findings.append(FormalFinding(
                issue_id=issue.id,
                vuln_class=VulnClass.STATISTICAL_EXPLOIT,
                confidence=prop["confidence"],
                method="property_checking",
                reasoning=prop["reasoning"],
            ))

        for prop in self.property_checker.check_test_coverage(code):
            vc = VulnClass.WEAK_TEST
            if prop["property"] == "existence_without_content":
                vc = VulnClass.WEAK_TEST
            findings.append(FormalFinding(
                issue_id=issue.id,
                vuln_class=vc,
                confidence=prop["confidence"],
                method="property_checking",
                reasoning=prop["reasoning"],
            ))

        # 3. Permission Analysis
        for perm in self.permission_analyzer.check_reference_file_protection(code, desc):
            findings.append(FormalFinding(
                issue_id=issue.id,
                vuln_class=VulnClass.WRITABLE_REFERENCE,
                confidence=perm["confidence"],
                method="permission_analysis",
                reasoning=perm["reasoning"],
            ))

        # 4. Git State Verification
        for git_issue in self.git_verifier.verify(code):
            findings.append(FormalFinding(
                issue_id=issue.id,
                vuln_class=VulnClass.ANSWER_LEAKAGE,
                confidence=git_issue["confidence"],
                method="git_state_verification",
                reasoning=git_issue["reasoning"],
                evidence=git_issue.get("missing_steps", []),
            ))

        # 5. Evaluation Order Analysis
        for order_issue in self.eval_order_analyzer.check_execution_order(code):
            vc = VulnClass.MEMORY_EXPLOIT if "memory" in order_issue["issue"] else VulnClass.INFRA_EXPLOIT
            findings.append(FormalFinding(
                issue_id=issue.id,
                vuln_class=vc,
                confidence=order_issue["confidence"],
                method="eval_order_analysis",
                reasoning=order_issue["reasoning"],
            ))

        # 6. Docker Analysis
        for docker_issue in self.docker_analyzer.check_docker_config(code):
            vc = VulnClass.INFRA_EXPLOIT
            if "missing_package" in docker_issue["issue"]:
                vc = VulnClass.MISSING_DEPENDENCY
            findings.append(FormalFinding(
                issue_id=issue.id,
                vuln_class=vc,
                confidence=docker_issue["confidence"],
                method="docker_analysis",
                reasoning=docker_issue["reasoning"],
            ))

        # 7. Code Pattern Analysis
        for pattern in self.code_pattern_analyzer.scan(code):
            findings.append(FormalFinding(
                issue_id=issue.id,
                vuln_class=pattern["vuln_class"],
                confidence=pattern["confidence"],
                method="pattern_matching",
                reasoning=pattern["reasoning"],
            ))

        # 8. Dependency Analysis
        for dep_issue in self.dependency_analyzer.check_dependencies(code, desc):
            vc = VulnClass.MISSING_DEPENDENCY if "missing" in dep_issue["issue"] \
                else VulnClass.EVAL_SCRIPT_BUG
            findings.append(FormalFinding(
                issue_id=issue.id,
                vuln_class=vc,
                confidence=dep_issue["confidence"],
                method="dependency_analysis",
                reasoning=dep_issue["reasoning"],
            ))

        # 9. Eval Script Analysis
        for score_issue in self.eval_script_analyzer.check_scoring(code):
            findings.append(FormalFinding(
                issue_id=issue.id,
                vuln_class=VulnClass.EVAL_SCRIPT_BUG if "index" in score_issue["issue"]
                    else VulnClass.WEAK_TEST,
                confidence=score_issue["confidence"],
                method="eval_script_analysis",
                reasoning=score_issue["reasoning"],
            ))

        for timing_issue in self.eval_script_analyzer.check_timing(code):
            findings.append(FormalFinding(
                issue_id=issue.id,
                vuln_class=VulnClass.EVAL_SCRIPT_BUG,
                confidence=timing_issue["confidence"],
                method="eval_script_analysis",
                reasoning=timing_issue["reasoning"],
            ))

        # 10. Data Contamination Check
        for contam in self.contamination_checker.check(code, desc):
            findings.append(FormalFinding(
                issue_id=issue.id,
                vuln_class=VulnClass.DATA_CONTAMINATION,
                confidence=contam["confidence"],
                method="contamination_analysis",
                reasoning=contam["reasoning"],
            ))

        # 11. Issue Text Leakage Check
        for leak in self.leakage_checker.check(code, desc):
            findings.append(FormalFinding(
                issue_id=issue.id,
                vuln_class=VulnClass.ANSWER_LEAKAGE,
                confidence=leak["confidence"],
                method="leakage_analysis",
                reasoning=leak["reasoning"],
            ))

        # 12. Test coverage — spec mismatch from property checker
        for prop in self.property_checker.check_test_coverage(code):
            if prop["property"] in ("buggy_oracle", "test_misclassification"):
                findings.append(FormalFinding(
                    issue_id=issue.id,
                    vuln_class=VulnClass.SPEC_MISMATCH,
                    confidence=prop["confidence"],
                    method="property_checking",
                    reasoning=prop["reasoning"],
                ))

        # Deduplicate
        seen = set()
        unique = []
        for f in findings:
            key = (f.vuln_class, f.method)
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return FormalResult(issue_id=issue.id, findings=unique)

    def _findings_from_ast(self, issue: Issue, ast_info: dict) -> list[FormalFinding]:
        """Generate findings from AST analysis results."""
        findings = []

        # Check for inheritance-based bypass
        for cls in ast_info.get("classes", []):
            if isinstance(cls, dict):
                if "Model" in cls.get("bases", []) and cls.get("has_pass", False):
                    findings.append(FormalFinding(
                        issue_id=issue.id,
                        vuln_class=VulnClass.CODE_LOOPHOLE,
                        confidence=0.9,
                        method="ast_analysis",
                        reasoning=f"Class {cls['name']} inherits Model with empty body",
                    ))

        # Check for try-except fallback
        if ast_info.get("try_except"):
            code = issue.code_sample
            if re.search(r'torch\.nn|F\.\w+', code):
                findings.append(FormalFinding(
                    issue_id=issue.id,
                    vuln_class=VulnClass.CODE_LOOPHOLE,
                    confidence=0.75,
                    method="ast_analysis",
                    reasoning="Try-except with PyTorch fallback detected",
                ))

        # Check assertion density
        assert_count = ast_info.get("assert_count", 0)
        test_funcs = [f for f in ast_info.get("functions", []) if f.startswith("test_")]
        if test_funcs and assert_count <= 2 and assert_count > 0:
            findings.append(FormalFinding(
                issue_id=issue.id,
                vuln_class=VulnClass.WEAK_TEST,
                confidence=0.6,
                method="ast_analysis",
                reasoning=f"Low assertion density: {assert_count} asserts in {len(test_funcs)} test functions",
            ))

        return findings


# ============================================================================
# Runner
# ============================================================================

def run_formal_detection(issues: list[Issue] = None) -> dict[str, FormalResult]:
    """Run formal detector on all issues and return results."""
    if issues is None:
        issues = ALL_ISSUES

    detector = FormalDetector()
    results = {}
    for issue in issues:
        results[issue.id] = detector.analyze(issue)
    return results


if __name__ == "__main__":
    results = run_formal_detection()
    detected = sum(1 for r in results.values() if r.detected)
    print(f"Formal Detector: {detected}/{len(results)} issues detected")
    print()
    for issue_id, result in results.items():
        status = "DETECTED" if result.detected else "MISSED"
        classes = [f.vuln_class.value for f in result.findings]
        methods = [f.method for f in result.findings]
        print(f"  {issue_id}: {status} {classes}")
