"""MVP benchmark audit pipeline with static + runtime verification stages.

Implemented stages:
- Benchmark ingestion/spec extraction
- Static policy checks
- Static verification (solver-backed when z3 is available)
- Runtime verification (instrumented subprocess/strace execution)
- Adversarial exploit template generation
- Risk correlation and scoring
"""

from __future__ import annotations

from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any
import hashlib
import json
import re
import ast
import shutil
import subprocess
import time


# ---------------------------------------------------------------------------
# Data schemas
# ---------------------------------------------------------------------------


@dataclass
class SandboxSpec:
    containerized: bool
    shared_process_with_evaluator: bool
    docker_socket_mounted: bool
    network_disabled: bool | None


@dataclass
class BenchmarkSpec:
    benchmark_id: str
    problem_id: str
    root_path: str
    submission_entrypoint: str | None
    evaluator_entrypoint: str | None
    runner_entrypoint: str | None
    checker_entrypoint: str | None
    score_channel: str
    hidden_assets: list[str]
    requires_network: bool | None
    requires_gpu: bool | None
    sandbox: SandboxSpec
    submission_outputs: list[str]
    policy_targets: list[str]


@dataclass
class Finding:
    finding_id: str
    stage: str
    severity: str
    category: str
    title: str
    entity: str
    evidence: str
    policy_ids: list[str] = field(default_factory=list)
    root_cause_cluster: str = ""


@dataclass
class StaticVerificationResult:
    verification_id: str
    property_id: str
    status: str  # proven_safe, counterexample_found, unknown
    severity: str
    title: str
    entity: str
    evidence: str
    counterexample: dict[str, float] | None = None


@dataclass
class RuntimeVerificationResult:
    check_id: str
    status: str  # pass, fail, warning, not_run
    severity: str
    title: str
    evidence: str


@dataclass
class ExploitResult:
    exploit_id: str
    template_name: str
    attack_surface: str
    enabled: bool
    expected_signal: str


# ---------------------------------------------------------------------------
# Ingestor: normalize benchmark into BenchmarkSpec
# ---------------------------------------------------------------------------


class BenchmarkIngestor:
    CODE_EXTS = {".py", ".sh", ".yaml", ".yml", ".json", "Dockerfile"}

    def build_spec(self, benchmark_root: str, benchmark_id: str = "custom") -> BenchmarkSpec:
        root = Path(benchmark_root)
        if not root.exists():
            raise FileNotFoundError(f"Benchmark path does not exist: {benchmark_root}")

        files = self._collect_files(root)
        evaluator = self._best_match(files, ["evaluator", "eval", "scorer", "score"])
        runner = self._best_match(files, ["runner", "harness", "docker", "compose"])
        checker = self._best_match(files, ["checker", "verify", "test"])
        submission = self._best_match(files, ["submission", "solution", "model", "agent"])

        hidden_assets = [
            str(p.relative_to(root))
            for p in files
            if re.search(r"(hidden|reference|baseline|ground.?truth|secret|seed|cache|score_config)", p.name, re.I)
        ]

        corpus = "\n".join(self._read_text(p) for p in files[:250])
        score_channel = self._infer_score_channel(corpus)
        submission_outputs = self._infer_submission_outputs(corpus)

        sandbox = SandboxSpec(
            containerized=self._contains_any(corpus, ["docker", "container", "podman"]),
            shared_process_with_evaluator=self._contains_any(
                corpus,
                ["importlib", "runpy", "exec(", "eval(", "sys.modules"],
            ),
            docker_socket_mounted=self._contains_any(corpus, ["/var/run/docker.sock"]),
            network_disabled=self._infer_network_policy(corpus),
        )

        requires_network = None
        if sandbox.network_disabled is True:
            requires_network = False
        elif self._contains_any(corpus, ["http://", "https://", "requests.", "socket("]):
            requires_network = True

        requires_gpu = self._contains_any(corpus, ["cuda", "nvidia", "gpu", "torch.cuda"]) or None

        return BenchmarkSpec(
            benchmark_id=benchmark_id,
            problem_id=root.name,
            root_path=str(root),
            submission_entrypoint=self._rel(root, submission),
            evaluator_entrypoint=self._rel(root, evaluator),
            runner_entrypoint=self._rel(root, runner),
            checker_entrypoint=self._rel(root, checker),
            score_channel=score_channel,
            hidden_assets=sorted(set(hidden_assets)),
            requires_network=requires_network,
            requires_gpu=bool(requires_gpu),
            sandbox=sandbox,
            submission_outputs=submission_outputs,
            policy_targets=[
                "P-SCORE-002",
                "P-ISO-001",
                "P-HIDDEN-003",
                "P-SANDBOX-004",
                "P-METRIC-005",
                "P-FORMULA-006",
                "P-RUNTIME-007",
            ],
        )

    def _collect_files(self, root: Path) -> list[Path]:
        files: list[Path] = []
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            if any(part.startswith(".") for part in p.parts):
                continue
            if p.suffix in self.CODE_EXTS or p.name.startswith("Dockerfile"):
                files.append(p)
        return sorted(files)

    def _best_match(self, files: list[Path], terms: list[str]) -> Path | None:
        ranked: list[tuple[int, Path]] = []
        for p in files:
            name = p.name.lower()
            score = sum(1 for t in terms if t in name)
            if score:
                ranked.append((score, p))
        if not ranked:
            return None
        ranked.sort(key=lambda x: (-x[0], len(str(x[1]))))
        return ranked[0][1]

    def _infer_score_channel(self, corpus: str) -> str:
        if re.search(r"last\s+numeric\s+line|stdout|stderr", corpus, re.I):
            return "stdout"
        if re.search(r"score\.json|result\.json|write.*score", corpus, re.I):
            return "structured_file"
        if re.search(r"api|http", corpus, re.I):
            return "network"
        return "unknown"

    def _infer_network_policy(self, corpus: str) -> bool | None:
        if re.search(r"--network=none|network_mode\s*:\s*none", corpus, re.I):
            return True
        if re.search(r"network_mode\s*:\s*host|--net=host", corpus, re.I):
            return False
        return None

    def _infer_submission_outputs(self, corpus: str) -> list[str]:
        outputs: list[str] = []
        for key in ["correct", "speedup", "complexity", "predictions", "details"]:
            if re.search(rf"[\['\"]{key}[\]'\"]", corpus):
                outputs.append(key)
        return sorted(set(outputs))

    def _contains_any(self, text: str, needles: list[str]) -> bool:
        t = text.lower()
        return any(n.lower() in t for n in needles)

    def _read_text(self, path: Path) -> str:
        try:
            return path.read_text(errors="replace")
        except OSError:
            return ""

    def _rel(self, root: Path, p: Path | None) -> str | None:
        return str(p.relative_to(root)) if p else None


# ---------------------------------------------------------------------------
# Static policy analyzer (lint-like)
# ---------------------------------------------------------------------------


class StaticPolicyAnalyzer:
    def analyze(self, spec: BenchmarkSpec) -> list[Finding]:
        findings: list[Finding] = []
        text = self._read_corpus(Path(spec.root_path))

        if spec.sandbox.shared_process_with_evaluator:
            findings.append(self._mk_finding(
                "shared_process_loader",
                "critical",
                "shared_address_space",
                "Submission likely executes in evaluator process",
                spec.evaluator_entrypoint or spec.runner_entrypoint or "unknown",
                "Detected importlib/runpy/exec/eval/sys.modules patterns.",
                ["P-ISO-001"],
                "shared_address_space",
            ))

        if spec.score_channel == "stdout":
            findings.append(self._mk_finding(
                "untrusted_stdout_score",
                "critical",
                "score_injection",
                "Score may be sourced from stdout/stderr",
                spec.runner_entrypoint or spec.evaluator_entrypoint or "unknown",
                "Found stdout/stderr and numeric parsing indicators in scoring path.",
                ["P-SCORE-002"],
                "untrusted_score_channel",
            ))

        if re.search(r"details\.(?:get\(|\[)(?:\"|')(correct|speedup|complexity)", text):
            findings.append(self._mk_finding(
                "self_reported_metric",
                "high",
                "self_certified_metrics",
                "Score appears to depend on submission self-reported metrics",
                spec.evaluator_entrypoint or "unknown",
                "Found score-relevant fields: correct/speedup/complexity.",
                ["P-METRIC-005"],
                "self_certified_metrics",
            ))

        if spec.hidden_assets:
            findings.append(self._mk_finding(
                "hidden_assets_present",
                "medium",
                "hidden_data_exposure",
                "Potentially sensitive hidden assets discovered",
                spec.root_path,
                f"Hidden-like files detected: {', '.join(spec.hidden_assets[:5])}",
                ["P-HIDDEN-003"],
                "hidden_data_exposure",
            ))

        if spec.sandbox.docker_socket_mounted:
            findings.append(self._mk_finding(
                "docker_socket_mount",
                "critical",
                "sandbox_escape",
                "Docker socket mount detected",
                spec.runner_entrypoint or "unknown",
                "Detected /var/run/docker.sock reference.",
                ["P-SANDBOX-004"],
                "sandbox_privilege",
            ))

        if spec.sandbox.network_disabled is not True:
            findings.append(self._mk_finding(
                "network_not_disabled",
                "high",
                "nondeterministic_network",
                "Network isolation policy missing or permissive",
                spec.runner_entrypoint or "unknown",
                "No explicit --network=none / network_mode:none policy found.",
                ["P-SANDBOX-004"],
                "sandbox_privilege",
            ))

        return findings

    def _mk_finding(
        self,
        key: str,
        severity: str,
        category: str,
        title: str,
        entity: str,
        evidence: str,
        policy_ids: list[str],
        root: str,
    ) -> Finding:
        finding_hash = hashlib.sha1(f"{key}:{entity}:{evidence}".encode()).hexdigest()[:10]
        return Finding(
            finding_id=f"AUD-{finding_hash}",
            stage="static_policy",
            severity=severity,
            category=category,
            title=title,
            entity=entity,
            evidence=evidence,
            policy_ids=policy_ids,
            root_cause_cluster=root,
        )

    def _read_corpus(self, root: Path) -> str:
        chunks: list[str] = []
        total = 0
        for p in root.rglob("*"):
            if p.is_file() and p.suffix in {".py", ".sh", ".yaml", ".yml", ".json"}:
                try:
                    text = p.read_text(errors="replace")
                    chunks.append(text)
                    total += len(text)
                except OSError:
                    pass
            if total > 2_000_000:
                break
        return "\n".join(chunks)


# ---------------------------------------------------------------------------
# Static verifier (solver-backed proofs on score formulas)
# ---------------------------------------------------------------------------


class ScoreFormulaExtractor(ast.NodeVisitor):
    """Extract score expressions from Python files.

    Heuristic: capture assignments where target name includes `score` and where the
    expression is arithmetic.
    """

    def __init__(self) -> None:
        self.formulas: list[tuple[str, ast.AST, int]] = []

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name) and "score" in target.id.lower():
                self.formulas.append((target.id, node.value, node.lineno))
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if isinstance(node.target, ast.Name) and "score" in node.target.id.lower() and node.value is not None:
            self.formulas.append((node.target.id, node.value, node.lineno))
        self.generic_visit(node)


class StaticVerifier:
    def __init__(self) -> None:
        try:
            import z3  # type: ignore
            self.z3 = z3
        except Exception:
            self.z3 = None

    def verify(self, spec: BenchmarkSpec) -> list[StaticVerificationResult]:
        if self.z3 is None:
            return [
                StaticVerificationResult(
                    verification_id="SV-Z3-UNAVAILABLE",
                    property_id="P-FORMULA-006",
                    status="unknown",
                    severity="medium",
                    title="Solver-backed verification unavailable",
                    entity=spec.evaluator_entrypoint or "unknown",
                    evidence="z3-solver is not installed in this environment; skipped proof checks.",
                )
            ]

        root = Path(spec.root_path)
        py_files = [p for p in root.rglob("*.py") if p.is_file()]
        results: list[StaticVerificationResult] = []
        found_formula = False

        for py_file in py_files[:200]:
            text = py_file.read_text(errors="replace")
            try:
                tree = ast.parse(text)
            except SyntaxError:
                continue

            extractor = ScoreFormulaExtractor()
            extractor.visit(tree)
            for score_name, expr, line in extractor.formulas:
                found_formula = True
                entity = f"{py_file.relative_to(root)}:{line}"
                results.extend(self._prove_formula_properties(score_name, expr, entity))

        if not found_formula:
            results.append(
                StaticVerificationResult(
                    verification_id="SV-NO-FORMULA",
                    property_id="P-FORMULA-006",
                    status="unknown",
                    severity="low",
                    title="No explicit score formula found for solver verification",
                    entity=spec.evaluator_entrypoint or "unknown",
                    evidence="Could not locate `score = ...`-style arithmetic assignments.",
                )
            )

        return results

    def _prove_formula_properties(self, score_name: str, expr: ast.AST, entity: str) -> list[StaticVerificationResult]:
        z3 = self.z3
        assert z3 is not None

        sym_env: dict[str, Any] = {}
        score_expr = self._to_z3(expr, sym_env)
        if score_expr is None:
            return [StaticVerificationResult(
                verification_id=self._mk_id("SV-PARSE", entity),
                property_id="P-FORMULA-006",
                status="unknown",
                severity="low",
                title=f"Could not symbolically translate formula for {score_name}",
                entity=entity,
                evidence="Expression contains unsupported syntax for current solver encoder.",
            )]

        out: list[StaticVerificationResult] = []

        # Property 1: bounded score in [0, 100]
        s = z3.Solver()
        s.add(z3.Or(score_expr < z3.RealVal("0"), score_expr > z3.RealVal("100")))
        if s.check() == z3.sat:
            model = s.model()
            ce = {str(d): float(model[d].as_decimal(8).replace("?", "")) for d in model.decls()}
            out.append(StaticVerificationResult(
                verification_id=self._mk_id("SV-BOUNDS", entity),
                property_id="P-FORMULA-006",
                status="counterexample_found",
                severity="high",
                title=f"Unbounded score expression for {score_name}",
                entity=entity,
                evidence="Solver found score value outside [0, 100].",
                counterexample=ce,
            ))
        else:
            out.append(StaticVerificationResult(
                verification_id=self._mk_id("SV-BOUNDS", entity),
                property_id="P-FORMULA-006",
                status="proven_safe",
                severity="low",
                title=f"Score expression bounded for {score_name}",
                entity=entity,
                evidence="No model satisfies score < 0 or score > 100.",
            ))

        # Property 2: denominator non-zero (for encoded divisions)
        for var in sym_env:
            if var.startswith("__den_"):
                s2 = z3.Solver()
                s2.add(sym_env[var] == z3.RealVal("0"))
                if s2.check() == z3.sat:
                    out.append(StaticVerificationResult(
                        verification_id=self._mk_id("SV-DIV0", entity),
                        property_id="P-FORMULA-006",
                        status="counterexample_found",
                        severity="high",
                        title=f"Possible division-by-zero in {score_name}",
                        entity=entity,
                        evidence="Solver can satisfy denominator == 0.",
                    ))
                else:
                    out.append(StaticVerificationResult(
                        verification_id=self._mk_id("SV-DIV0", entity),
                        property_id="P-FORMULA-006",
                        status="proven_safe",
                        severity="low",
                        title=f"Denominator non-zero for {score_name}",
                        entity=entity,
                        evidence="No model satisfies denominator == 0.",
                    ))

        return out

    def _to_z3(self, node: ast.AST, env: dict[str, Any]) -> Any | None:
        z3 = self.z3
        assert z3 is not None

        if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return z3.RealVal(str(node.value))
        if isinstance(node, ast.Name):
            if node.id not in env:
                env[node.id] = z3.Real(node.id)
            return env[node.id]
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
            v = self._to_z3(node.operand, env)
            return -v if v is not None else None
        if isinstance(node, ast.BinOp):
            left = self._to_z3(node.left, env)
            right = self._to_z3(node.right, env)
            if left is None or right is None:
                return None
            if isinstance(node.op, ast.Add):
                return left + right
            if isinstance(node.op, ast.Sub):
                return left - right
            if isinstance(node.op, ast.Mult):
                return left * right
            if isinstance(node.op, ast.Div):
                den_name = f"__den_{len([k for k in env if k.startswith('__den_')])}"
                env[den_name] = right
                return left / right
            return None
        return None

    def _mk_id(self, key: str, entity: str) -> str:
        return f"{key}-{hashlib.sha1(entity.encode()).hexdigest()[:8]}"


# ---------------------------------------------------------------------------
# Runtime verifier (instrumented execution)
# ---------------------------------------------------------------------------


class RuntimeVerifier:
    def verify(
        self,
        spec: BenchmarkSpec,
        run_cmd: str | None,
        timeout_s: int = 120,
    ) -> list[RuntimeVerificationResult]:
        if not run_cmd:
            return [RuntimeVerificationResult(
                check_id="RV-NOT-RUN",
                status="not_run",
                severity="low",
                title="Runtime verification not executed",
                evidence="No --run-cmd provided.",
            )]

        root = Path(spec.root_path)
        before = self._snapshot_sensitive_files(root, spec)

        trace_file = root / ".audit_runtime_trace.txt"
        use_strace = shutil.which("strace") is not None
        if use_strace:
            cmd = f"strace -ff -o {trace_file} -e trace=openat,connect,execve {run_cmd}"
        else:
            cmd = run_cmd

        start = time.time()
        try:
            proc = subprocess.run(
                cmd,
                shell=True,
                cwd=root,
                capture_output=True,
                text=True,
                timeout=timeout_s,
            )
            timed_out = False
        except subprocess.TimeoutExpired as e:
            proc = e
            timed_out = True
        duration = time.time() - start

        after = self._snapshot_sensitive_files(root, spec)
        results: list[RuntimeVerificationResult] = []

        if timed_out:
            results.append(RuntimeVerificationResult(
                check_id="RV-TIMEOUT",
                status="warning",
                severity="medium",
                title="Runtime verification command timed out",
                evidence=f"Command exceeded {timeout_s}s.",
            ))
            return results

        assert isinstance(proc, subprocess.CompletedProcess)
        results.append(RuntimeVerificationResult(
            check_id="RV-EXIT",
            status="pass" if proc.returncode == 0 else "warning",
            severity="low" if proc.returncode == 0 else "medium",
            title="Runtime command exit status",
            evidence=f"returncode={proc.returncode}, duration_s={duration:.2f}",
        ))

        # Check mutable scorer/hidden files
        mutated = [p for p in before if before[p] != after.get(p)]
        if mutated:
            results.append(RuntimeVerificationResult(
                check_id="RV-MUTATION",
                status="fail",
                severity="high",
                title="Sensitive files modified during runtime execution",
                evidence=", ".join(mutated[:10]),
            ))
        else:
            results.append(RuntimeVerificationResult(
                check_id="RV-MUTATION",
                status="pass",
                severity="low",
                title="No sensitive file mutation observed",
                evidence="Tracked evaluator/checker/hidden files remained unchanged.",
            ))

        # Heuristic score provenance check
        tail = (proc.stdout or "")[-2000:]
        if spec.score_channel == "stdout" and re.search(r"\n\s*[-+]?\d+(?:\.\d+)?\s*$", tail):
            results.append(RuntimeVerificationResult(
                check_id="RV-SCORE-STDOUT",
                status="warning",
                severity="high",
                title="Score-like numeric tail detected on stdout",
                evidence="Potential untrusted score provenance from stdout numeric tail.",
            ))
        else:
            results.append(RuntimeVerificationResult(
                check_id="RV-SCORE-STDOUT",
                status="pass",
                severity="low",
                title="No suspicious stdout score tail detected",
                evidence="Did not observe numeric-tail score pattern in stdout.",
            ))

        # Optional trace-based network check
        if use_strace:
            trace_blob = self._read_trace_files(trace_file)
            if re.search(r"connect\(", trace_blob):
                sev = "high" if spec.sandbox.network_disabled is True else "medium"
                st = "fail" if spec.sandbox.network_disabled is True else "warning"
                results.append(RuntimeVerificationResult(
                    check_id="RV-NETWORK",
                    status=st,
                    severity=sev,
                    title="Outbound network syscall observed",
                    evidence="strace captured connect() during runtime verification.",
                ))
            else:
                results.append(RuntimeVerificationResult(
                    check_id="RV-NETWORK",
                    status="pass",
                    severity="low",
                    title="No outbound network syscall observed",
                    evidence="No connect() syscall found in runtime trace.",
                ))
        else:
            results.append(RuntimeVerificationResult(
                check_id="RV-NETWORK",
                status="warning",
                severity="low",
                title="strace unavailable; limited runtime network verification",
                evidence="Install strace to enable syscall-level runtime checks.",
            ))

        return results

    def _snapshot_sensitive_files(self, root: Path, spec: BenchmarkSpec) -> dict[str, str]:
        targets: set[Path] = set()
        for rel in [spec.evaluator_entrypoint, spec.checker_entrypoint, spec.runner_entrypoint]:
            if rel:
                p = root / rel
                if p.exists() and p.is_file():
                    targets.add(p)
        for rel in spec.hidden_assets[:200]:
            p = root / rel
            if p.exists() and p.is_file():
                targets.add(p)

        snap: dict[str, str] = {}
        for p in targets:
            try:
                h = hashlib.sha256(p.read_bytes()).hexdigest()
            except OSError:
                h = "<unreadable>"
            snap[str(p.relative_to(root))] = h
        return snap

    def _read_trace_files(self, base: Path) -> str:
        # strace -ff creates suffixes like <file>.<pid>
        blobs: list[str] = []
        parent = base.parent
        prefix = base.name
        for p in parent.glob(f"{prefix}*"):
            if p.is_file():
                try:
                    blobs.append(p.read_text(errors="replace"))
                except OSError:
                    pass
        return "\n".join(blobs)


# ---------------------------------------------------------------------------
# Adversarial test generation (template library)
# ---------------------------------------------------------------------------


UNIVERSAL_EXPLOITS: list[tuple[str, str, str]] = [
    ("EXP-IMPORT-001", "import_time_file_overwrite", "mutable_scoring_state"),
    ("EXP-STDOUT-001", "stdout_tail_injection", "stdout_score_channel"),
    ("EXP-ATEXIT-001", "atexit_fake_score", "stdout_score_channel"),
    ("EXP-PATCH-001", "monkey_patch_helpers", "shared_address_space"),
    ("EXP-HIDDEN-001", "hidden_asset_scan", "hidden_data_exposure"),
    ("EXP-CONFIG-001", "score_config_poison", "mutable_scoring_state"),
    ("EXP-NET-001", "network_exfil_probe", "sandbox_network"),
    ("EXP-METRIC-001", "self_report_forgery", "self_certified_metrics"),
]


class AdversarialTestGenerator:
    def generate(self, spec: BenchmarkSpec) -> list[ExploitResult]:
        enabled = []
        for exploit_id, template_name, surface in UNIVERSAL_EXPLOITS:
            should_enable = self._is_relevant(template_name, spec)
            enabled.append(ExploitResult(
                exploit_id=exploit_id,
                template_name=template_name,
                attack_surface=surface,
                enabled=should_enable,
                expected_signal=self._expected_signal(template_name),
            ))
        return enabled

    def _is_relevant(self, template_name: str, spec: BenchmarkSpec) -> bool:
        if template_name in {"stdout_tail_injection", "atexit_fake_score"}:
            return spec.score_channel == "stdout"
        if template_name == "network_exfil_probe":
            return spec.sandbox.network_disabled is not True
        if template_name == "monkey_patch_helpers":
            return spec.sandbox.shared_process_with_evaluator
        return True

    def _expected_signal(self, template_name: str) -> str:
        mapping = {
            "stdout_tail_injection": "accepted_score_owner=submission",
            "atexit_fake_score": "late_numeric_line_accepted",
            "import_time_file_overwrite": "forbidden_write:evaluator_root",
            "hidden_asset_scan": "hidden_asset_read_detected",
            "score_config_poison": "config_digest_changed_before_scoring",
            "self_report_forgery": "score_changed_without_correctness",
            "network_exfil_probe": "unexpected_outbound_connection",
            "monkey_patch_helpers": "module_symbol_hash_changed",
        }
        return mapping.get(template_name, "signal_expected")


# ---------------------------------------------------------------------------
# Correlator
# ---------------------------------------------------------------------------


class FindingsCorrelator:
    ROOT_CAUSES = {
        "shared_address_space": "no_isolation",
        "hidden_data_exposure": "hidden_data_exposure",
        "mutable_scoring_state": "mutable_scoring_state",
        "self_certified_metrics": "self_certified_metrics",
        "sandbox_privilege": "inadequate_sandbox_configuration",
        "untrusted_score_channel": "untrusted_score_channel",
        "nondeterministic_network": "nondeterministic_network_dependency",
    }

    def correlate(
        self,
        findings: list[Finding],
        static_verification: list[StaticVerificationResult],
        runtime_verification: list[RuntimeVerificationResult],
    ) -> dict[str, Any]:
        clusters: dict[str, list[str]] = {}
        for f in findings:
            root = self.ROOT_CAUSES.get(f.root_cause_cluster, f.root_cause_cluster or "other")
            clusters.setdefault(root, []).append(f.finding_id)

        severity_weights = {"low": 1, "medium": 2, "high": 4, "critical": 7}
        risk_score = sum(severity_weights.get(f.severity, 1) for f in findings)

        for sv in static_verification:
            if sv.status == "counterexample_found":
                risk_score += severity_weights.get(sv.severity, 1)

        for rv in runtime_verification:
            if rv.status in {"fail", "warning"}:
                risk_score += severity_weights.get(rv.severity, 1)

        risk_band = "low"
        if risk_score >= 24:
            risk_band = "critical"
        elif risk_score >= 14:
            risk_band = "high"
        elif risk_score >= 7:
            risk_band = "medium"

        return {
            "risk_score": risk_score,
            "risk_band": risk_band,
            "root_cause_clusters": clusters,
            "finding_count": len(findings),
            "static_verification_count": len(static_verification),
            "runtime_verification_count": len(runtime_verification),
        }


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------


class AuditPipeline:
    def __init__(self) -> None:
        self.ingestor = BenchmarkIngestor()
        self.static = StaticPolicyAnalyzer()
        self.static_verifier = StaticVerifier()
        self.runtime_verifier = RuntimeVerifier()
        self.adversarial = AdversarialTestGenerator()
        self.correlator = FindingsCorrelator()

    def run(
        self,
        benchmark_root: str,
        benchmark_id: str = "custom",
        run_cmd: str | None = None,
        timeout_s: int = 120,
    ) -> dict[str, Any]:
        spec = self.ingestor.build_spec(benchmark_root=benchmark_root, benchmark_id=benchmark_id)
        findings = self.static.analyze(spec)
        static_verification = self.static_verifier.verify(spec)
        runtime_verification = self.runtime_verifier.verify(spec, run_cmd=run_cmd, timeout_s=timeout_s)
        exploits = self.adversarial.generate(spec)
        summary = self.correlator.correlate(findings, static_verification, runtime_verification)

        return {
            "benchmark_spec": asdict(spec),
            "findings": [asdict(f) for f in findings],
            "static_verification": [asdict(r) for r in static_verification],
            "runtime_verification": [asdict(r) for r in runtime_verification],
            "exploit_plan": [asdict(e) for e in exploits],
            "summary": summary,
        }


def run_audit(
    benchmark_root: str,
    benchmark_id: str = "custom",
    run_cmd: str | None = None,
    timeout_s: int = 120,
) -> dict[str, Any]:
    return AuditPipeline().run(
        benchmark_root=benchmark_root,
        benchmark_id=benchmark_id,
        run_cmd=run_cmd,
        timeout_s=timeout_s,
    )


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Run benchmark audit pipeline")
    parser.add_argument("path", help="Benchmark repository/problem path")
    parser.add_argument("--benchmark-id", default="custom")
    parser.add_argument("--run-cmd", default="", help="Optional runtime verification command")
    parser.add_argument("--timeout-s", type=int, default=120)
    parser.add_argument("--out", default="", help="Optional output json path")
    args = parser.parse_args()

    report = run_audit(
        args.path,
        benchmark_id=args.benchmark_id,
        run_cmd=args.run_cmd or None,
        timeout_s=args.timeout_s,
    )
    rendered = json.dumps(report, indent=2)
    if args.out:
        Path(args.out).write_text(rendered)
        print(f"Wrote audit report to {args.out}")
    else:
        print(rendered)


if __name__ == "__main__":
    main()
