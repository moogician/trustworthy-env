#!/usr/bin/env python3
"""
Benchmark Vulnerability Detector CLI
======================================
Scan benchmark evaluation code for reward hacking vulnerabilities.

Usage:
  # Scan a single file
  python detect.py scan path/to/eval_script.py

  # Scan a directory (e.g., a benchmark repo)
  python detect.py scan path/to/benchmark/

  # Scan with specific detector only
  python detect.py scan path/to/benchmark/ --detector llm
  python detect.py scan path/to/benchmark/ --detector formal

  # Run against the built-in catalog (regression test)
  python detect.py test

  # Show summary of built-in catalog
  python detect.py catalog
"""

import argparse
import os
import sys
import glob as globmod
from pathlib import Path
from dataclasses import dataclass

# Ensure imports work
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from catalog import Issue, VulnClass, Benchmark, ALL_ISSUES
from llm_detector import LLMDetector, Finding, DetectionResult
from formal_detector import FormalDetector, FormalFinding, FormalResult
from audit_mvp import run_audit
from poc_verifier import PoCVerifier, write_verification_report, write_verification_markdown


# ============================================================================
# File scanner: wraps both detectors to work on raw files
# ============================================================================

class FileScanner:
    """Scan actual files/directories for benchmark vulnerabilities."""

    # File patterns likely to contain evaluation code
    EVAL_PATTERNS = [
        "**/*test*.py", "**/*eval*.py", "**/*check*.py", "**/*verify*.py",
        "**/*score*.py", "**/*grade*.py", "**/*harness*.py", "**/*runner*.py",
        "**/*bench*.py", "**/Dockerfile*", "**/*setup*.sh", "**/*test*.sh",
        "**/*timing*.py", "**/*metric*.py",
    ]

    # Skip patterns
    SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", "env"}

    def __init__(self, use_llm=True, use_formal=True):
        self.llm = LLMDetector() if use_llm else None
        self.formal = FormalDetector() if use_formal else None

    def scan_file(self, filepath: str) -> dict:
        """Scan a single file and return findings from both detectors."""
        try:
            with open(filepath, "r", errors="replace") as f:
                code = f.read()
        except (OSError, UnicodeDecodeError) as e:
            return {"file": filepath, "error": str(e), "findings": []}

        # Create a synthetic Issue object for the detectors
        issue = Issue(
            id=os.path.basename(filepath),
            benchmark=Benchmark.TERMINAL_BENCH,  # placeholder
            vuln_classes=[],
            title=os.path.basename(filepath),
            description=f"File: {filepath}",
            code_sample=code,
            detection_hints=[],
        )

        all_findings = []

        if self.llm:
            result = self.llm.analyze(issue)
            for f in result.findings:
                all_findings.append({
                    "detector": "llm",
                    "class": f.vuln_class.value,
                    "confidence": f.confidence,
                    "reasoning": f.reasoning,
                    "evidence": f.evidence,
                })

        if self.formal:
            result = self.formal.analyze(issue)
            for f in result.findings:
                all_findings.append({
                    "detector": "formal",
                    "class": f.vuln_class.value,
                    "confidence": f.confidence,
                    "method": f.method,
                    "reasoning": f.reasoning,
                })

        return {
            "file": filepath,
            "findings": all_findings,
            "vuln_count": len(all_findings),
        }

    def scan_directory(self, dirpath: str, patterns=None) -> list[dict]:
        """Scan a directory for evaluation files and analyze them."""
        if patterns is None:
            patterns = self.EVAL_PATTERNS

        files_to_scan = set()
        for pattern in patterns:
            for match in globmod.glob(os.path.join(dirpath, pattern), recursive=True):
                # Skip excluded dirs
                parts = Path(match).parts
                if not any(skip in parts for skip in self.SKIP_DIRS):
                    files_to_scan.add(match)

        results = []
        for filepath in sorted(files_to_scan):
            result = self.scan_file(filepath)
            if result["findings"]:  # Only include files with findings
                results.append(result)

        return results


# ============================================================================
# CLI
# ============================================================================

def cmd_scan(args):
    """Scan files/directories for vulnerabilities."""
    detector_flags = {
        "both": (True, True),
        "llm": (True, False),
        "formal": (False, True),
    }
    use_llm, use_formal = detector_flags[args.detector]
    scanner = FileScanner(use_llm=use_llm, use_formal=use_formal)

    target = args.path
    if os.path.isfile(target):
        results = [scanner.scan_file(target)]
    elif os.path.isdir(target):
        print(f"Scanning directory: {target}")
        print(f"Detector: {args.detector}")
        print()
        results = scanner.scan_directory(target)
    else:
        print(f"Error: {target} is not a file or directory", file=sys.stderr)
        sys.exit(1)

    # Print results
    total_findings = 0
    for result in results:
        if result.get("error"):
            print(f"  ERROR {result['file']}: {result['error']}")
            continue

        n = result["vuln_count"]
        total_findings += n
        if n == 0 and not args.verbose:
            continue

        rel = os.path.relpath(result["file"], target) if os.path.isdir(target) else result["file"]
        print(f"  {rel}: {n} finding(s)")

        for f in result["findings"]:
            det = f["detector"].upper()
            cls = f["class"]
            conf = f["confidence"]
            reason = f["reasoning"]
            print(f"    [{det}] {cls} (conf={conf:.0%}): {reason}")

        if result["findings"]:
            print()

    # Summary
    files_with_findings = sum(1 for r in results if r.get("vuln_count", 0) > 0)
    print(f"--- Summary ---")
    print(f"  Files scanned: {len(results)}")
    print(f"  Files with findings: {files_with_findings}")
    print(f"  Total findings: {total_findings}")

    # Aggregate by class
    class_counts = {}
    for r in results:
        for f in r.get("findings", []):
            cls = f["class"]
            class_counts[cls] = class_counts.get(cls, 0) + 1

    if class_counts:
        print(f"\n  By vulnerability class:")
        for cls, count in sorted(class_counts.items(), key=lambda x: -x[1]):
            print(f"    {cls}: {count}")




def cmd_audit(args):
    """Run benchmark audit pipeline against a benchmark repo/problem directory."""
    report = run_audit(
        args.path,
        benchmark_id=args.benchmark_id,
        run_cmd=args.run_cmd or None,
        timeout_s=args.timeout_s,
        use_llm=not args.no_llm,
        model=getattr(args, "model", None),
        api_key=getattr(args, "api_key", None),
        base_url=getattr(args, "base_url", None),
    )

    if args.out:
        import json
        from pathlib import Path
        Path(args.out).write_text(json.dumps(report, indent=2))
        print(f"Wrote audit report to {args.out}")

    summary = report["summary"]
    print(f"Risk band: {summary['risk_band']} (score={summary['risk_score']})")
    print(f"Findings: {summary['finding_count']}")
    print(f"Static verification checks: {summary['static_verification_count']}")
    print(f"Runtime verification checks: {summary['runtime_verification_count']}")

    for f in report["findings"]:
        print(f"  [POLICY/{f['severity'].upper()}] {f['category']} :: {f['title']} ({f['entity']})")

    for v in report.get("static_verification", []):
        print(f"  [STATIC/{v['status'].upper()}] {v['title']} ({v['entity']})")

    for v in report.get("runtime_verification", []):
        print(f"  [RUNTIME/{v['status'].upper()}] {v['title']}")


def cmd_verify(args):
    """Run agentic PoC verification on an audit report."""
    verifier = PoCVerifier(
        model=args.model,
        api_key=args.api_key,
        base_url=args.base_url,
        timeout_s=args.timeout_s,
        max_findings=args.max_findings,
        max_agent_turns=args.max_agent_turns,
        verbose=args.verbose,
        skip_analysis=args.skip_analysis,
        benchmark_root=args.benchmark_root,
    )

    if not verifier.available:
        print("[verify] ERROR: LLM client required for agentic verification.")
        print("[verify] Provide --model, --api-key, and --base-url flags.")
        sys.exit(1)

    report = verifier.verify_report(args.report)

    # Default output paths
    base = os.path.splitext(os.path.basename(args.report))[0]
    out_dir = os.path.dirname(args.report) or "."

    json_path = args.out_json or os.path.join(out_dir, f"{base}-verified.json")
    md_path = args.out_md or os.path.join(out_dir, f"{base}-verified.md")

    write_verification_report(report, json_path)
    write_verification_markdown(report, md_path)


def cmd_test(args):
    """Run against built-in catalog (regression test)."""
    from runner import run_comparison
    run_comparison()


def cmd_catalog(args):
    """Show summary of built-in catalog."""
    from catalog import summary
    summary()


def main():
    parser = argparse.ArgumentParser(
        description="Benchmark Vulnerability Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python detect.py scan ./KernelBench/
  python detect.py scan eval.py --detector formal
  python detect.py test
  python detect.py catalog
  python detect.py audit ./kernelbench-demo --benchmark-id kernelbench
  python detect.py audit ./benchmark --run-cmd "python3 evaluator.py" --timeout-s 90
  python detect.py verify data/reports/FrontierCS-audit.json --model vertex_ai/claude-opus-4-6
        """,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # scan
    p_scan = subparsers.add_parser("scan", help="Scan files/directories for vulnerabilities")
    p_scan.add_argument("path", help="File or directory to scan")
    p_scan.add_argument("--detector", choices=["both", "llm", "formal"], default="both",
                        help="Which detector to use (default: both)")
    p_scan.add_argument("--verbose", "-v", action="store_true",
                        help="Show files with no findings too")
    p_scan.set_defaults(func=cmd_scan)

    # test
    p_test = subparsers.add_parser("test", help="Run regression test against built-in catalog")
    p_test.set_defaults(func=cmd_test)

    # catalog
    p_cat = subparsers.add_parser("catalog", help="Show built-in issue catalog summary")
    p_cat.set_defaults(func=cmd_catalog)

    # audit
    p_audit = subparsers.add_parser("audit", help="Run MVP benchmark audit pipeline")
    p_audit.add_argument("path", help="Benchmark repository/problem path")
    p_audit.add_argument("--benchmark-id", default="custom", help="Benchmark identifier")
    p_audit.add_argument("--run-cmd", default="", help="Optional command to execute for runtime verification")
    p_audit.add_argument("--timeout-s", type=int, default=120, help="Timeout in seconds for runtime verification command")
    p_audit.add_argument("--out", default="", help="Optional path to write JSON report")
    p_audit.add_argument("--no-llm", action="store_true", help="Skip real LLM API calls (heuristics only)")
    p_audit.add_argument("--model", default=None, help="LLM model name (default: gpt-4o-mini, or AUDIT_MODEL env)")
    p_audit.add_argument("--api-key", default=None, help="LLM API key (or set AUDIT_API_KEY / MODEL_API_KEY env)")
    p_audit.add_argument("--base-url", default=None, help="LLM API base URL (or set AUDIT_BASE_URL env)")
    p_audit.set_defaults(func=cmd_audit)

    # verify
    p_verify = subparsers.add_parser("verify", help="Agentic PoC verification of audit findings")
    p_verify.add_argument("report", help="Path to audit JSON report")
    p_verify.add_argument("--benchmark-root", default=None, help="Override benchmark root path")
    p_verify.add_argument("--out-json", default="", help="Output JSON verification report path")
    p_verify.add_argument("--out-md", default="", help="Output markdown verification report path")
    p_verify.add_argument("--model", default=None, help="LLM model name")
    p_verify.add_argument("--api-key", default=None, help="LLM API key")
    p_verify.add_argument("--base-url", default=None, help="LLM API base URL")
    p_verify.add_argument("--timeout-s", type=int, default=120, help="Per-command execution timeout (default: 120s)")
    p_verify.add_argument("--max-findings", type=int, default=None, help="Max findings to verify")
    p_verify.add_argument("--max-agent-turns", type=int, default=20, help="Max agent turns per finding (default: 20)")
    p_verify.add_argument("--skip-analysis", action="store_true", help="Skip repo analysis phase")
    p_verify.add_argument("-v", "--verbose", action="store_true", help="Show agent tool calls")
    p_verify.set_defaults(func=cmd_verify)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
