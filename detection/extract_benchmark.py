#!/usr/bin/env python3
"""LLM-based benchmark structure extraction.

Given a benchmark repository, uses an LLM to identify:
- Problem/task directories and their structure
- Evaluator, scorer, and checker scripts
- Submission entrypoints and expected output format
- Hidden/reference assets (ground truth, baselines)
- Sandbox and isolation configuration

This supplements the heuristic-based BenchmarkIngestor in audit_mvp.py
by reasoning about README files, code comments, and non-obvious naming
conventions that pattern matching would miss.

Usage:
  python extract_benchmark.py /path/to/benchmark --benchmark-id MyBench
  python extract_benchmark.py /path/to/benchmark --benchmark-id MyBench --model gpt-4o --api-key sk-...
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# File collection
# ---------------------------------------------------------------------------

SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", "env", ".tox", ".mypy_cache"}
CODE_EXTS = {".py", ".sh", ".yaml", ".yml", ".json", ".toml", ".cfg", ".ini", ".js", ".ts"}
DOC_NAMES = {"README.md", "readme.md", "README.rst", "CONTRIBUTING.md", "EVAL.md", "INSTALL.md"}
MAX_FILE_CHARS = 8000
MAX_TOTAL_CHARS = 120_000


def collect_tree(root: Path) -> str:
    """Return a tree listing of the repo (directories + files) for context."""
    lines: list[str] = []
    for p in sorted(root.rglob("*")):
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        rel = p.relative_to(root)
        if len(lines) > 500:
            lines.append("... (truncated)")
            break
        lines.append(str(rel))
    return "\n".join(lines)


def collect_key_files(root: Path) -> list[tuple[str, str]]:
    """Collect the most informative files: READMEs, configs, eval scripts."""
    files: list[tuple[str, str]] = []
    total = 0

    # Priority 1: documentation
    for p in sorted(root.rglob("*")):
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.name in DOC_NAMES and p.is_file():
            text = _safe_read(p)
            if text:
                files.append((str(p.relative_to(root)), text[:MAX_FILE_CHARS]))
                total += len(files[-1][1])

    # Priority 2: config files (pyproject.toml, Dockerfile, docker-compose, Makefile)
    config_patterns = {"pyproject.toml", "setup.py", "setup.cfg", "Dockerfile",
                       "docker-compose.yml", "docker-compose.yaml", "Makefile", "package.json"}
    for p in sorted(root.rglob("*")):
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.name in config_patterns and p.is_file() and total < MAX_TOTAL_CHARS:
            text = _safe_read(p)
            if text:
                files.append((str(p.relative_to(root)), text[:MAX_FILE_CHARS]))
                total += len(files[-1][1])

    # Priority 3: likely evaluator/scorer/test scripts
    eval_keywords = {"eval", "score", "grade", "check", "verify", "judge", "test", "harness", "runner"}
    for p in sorted(root.rglob("*")):
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if not p.is_file() or p.suffix not in CODE_EXTS:
            continue
        if total >= MAX_TOTAL_CHARS:
            break
        name_lower = p.stem.lower()
        if any(kw in name_lower for kw in eval_keywords):
            text = _safe_read(p)
            if text:
                files.append((str(p.relative_to(root)), text[:MAX_FILE_CHARS]))
                total += len(files[-1][1])

    return files


def _safe_read(p: Path) -> str | None:
    try:
        return p.read_text(errors="replace")
    except OSError:
        return None


# ---------------------------------------------------------------------------
# LLM extraction
# ---------------------------------------------------------------------------

EXTRACTION_PROMPT = """\
You are a security auditor analyzing an AI benchmark repository.
Given the file tree and key file contents below, identify the benchmark's structure.

Return a JSON object with these fields:
{{
  "benchmark_name": "Human-readable name",
  "description": "One-line description of what this benchmark evaluates",
  "problems": {{
    "directory_pattern": "glob pattern for problem dirs/files (e.g. 'problems/*/problem.yaml')",
    "count_estimate": <int or null>,
    "example_problems": ["list", "of", "2-3", "example", "problem", "names"]
  }},
  "evaluator": {{
    "entrypoints": ["relative/path/to/main/eval/script.py"],
    "description": "How evaluation works"
  }},
  "scorer": {{
    "entrypoints": ["relative/path/to/scoring/script.py"],
    "score_channel": "stdout | structured_file | network | unknown",
    "metric_names": ["accuracy", "speedup", "etc"]
  }},
  "submission": {{
    "entrypoints": ["relative/path/to/expected/submission/format"],
    "expected_output": "Description of what a submission produces"
  }},
  "hidden_assets": ["relative/paths/to/ground_truth", "reference_outputs", "etc"],
  "sandbox": {{
    "containerized": true/false,
    "isolation_notes": "How solutions are isolated (Docker, subprocess, etc)"
  }},
  "potential_concerns": [
    "Brief notes on anything that looks exploitable or weak from a security audit perspective"
  ]
}}

Be precise with file paths — only reference files that actually exist in the tree.
If you cannot determine a field, use null.

## File tree
{tree}

## Key files
{files}
"""


def call_llm(prompt: str, model: str | None, api_key: str | None, base_url: str | None) -> str:
    """Call an LLM via litellm (if available) or a basic HTTP fallback."""
    model = model or os.environ.get("AUDIT_MODEL", "gpt-4o-mini")
    api_key = api_key or os.environ.get("AUDIT_API_KEY") or os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("OPENAI_API_KEY")
    base_url = base_url or os.environ.get("AUDIT_BASE_URL")

    if not api_key:
        raise RuntimeError("No API key provided. Set AUDIT_API_KEY, ANTHROPIC_API_KEY, or OPENAI_API_KEY.")

    # Try litellm first
    try:
        import litellm
        litellm.api_key = api_key
        if base_url:
            litellm.api_base = base_url
        response = litellm.completion(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            max_tokens=4096,
        )
        return response.choices[0].message.content
    except ImportError:
        pass

    # Fallback: direct OpenAI-compatible API call
    import urllib.request
    url = (base_url or "https://api.openai.com/v1") + "/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    body = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.2,
        "max_tokens": 4096,
    }).encode()
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = json.loads(resp.read())
    return data["choices"][0]["message"]["content"]


def extract(benchmark_root: str, benchmark_id: str,
            model: str | None = None, api_key: str | None = None,
            base_url: str | None = None) -> dict:
    root = Path(benchmark_root)
    if not root.exists():
        raise FileNotFoundError(f"Benchmark path does not exist: {benchmark_root}")

    print(f"Collecting file tree from {root}...")
    tree = collect_tree(root)

    print("Collecting key files for analysis...")
    key_files = collect_key_files(root)
    files_block = ""
    for rel_path, content in key_files:
        files_block += f"\n### {rel_path}\n```\n{content}\n```\n"

    prompt = EXTRACTION_PROMPT.format(tree=tree, files=files_block)
    print(f"Sending to LLM ({model or os.environ.get('AUDIT_MODEL', 'gpt-4o-mini')})...")
    raw = call_llm(prompt, model=model, api_key=api_key, base_url=base_url)

    # Parse JSON from response (handle markdown code fences)
    raw = raw.strip()
    if raw.startswith("```"):
        raw = raw.split("\n", 1)[1]
        if raw.endswith("```"):
            raw = raw[:-3]

    try:
        result = json.loads(raw)
    except json.JSONDecodeError:
        # Try to extract JSON from mixed text
        import re
        match = re.search(r"\{.*\}", raw, re.DOTALL)
        if match:
            result = json.loads(match.group())
        else:
            print(f"Warning: could not parse LLM response as JSON", file=sys.stderr)
            result = {"raw_response": raw}

    result["benchmark_id"] = benchmark_id
    result["benchmark_root"] = str(root.resolve())

    # Write extraction result
    out_path = root / ".benchmark_spec.json"
    out_path.write_text(json.dumps(result, indent=2))
    print(f"Wrote benchmark spec to {out_path}")

    # Print summary
    print(f"\n{'=' * 60}")
    print(f"Benchmark: {result.get('benchmark_name', benchmark_id)}")
    print(f"Description: {result.get('description', 'N/A')}")
    if result.get("evaluator", {}).get("entrypoints"):
        print(f"Evaluator: {', '.join(result['evaluator']['entrypoints'])}")
    if result.get("scorer", {}).get("entrypoints"):
        print(f"Scorer: {', '.join(result['scorer']['entrypoints'])}")
    if result.get("problems", {}).get("count_estimate"):
        print(f"Problems: ~{result['problems']['count_estimate']}")
    if result.get("potential_concerns"):
        print(f"Potential concerns: {len(result['potential_concerns'])}")
        for c in result["potential_concerns"]:
            print(f"  - {c}")
    print(f"{'=' * 60}")

    return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="LLM-based benchmark structure extraction",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python extract_benchmark.py /path/to/benchmark --benchmark-id MyBench
  python extract_benchmark.py /path/to/benchmark --benchmark-id MyBench --model gpt-4o
        """,
    )
    parser.add_argument("path", help="Benchmark repository path")
    parser.add_argument("--benchmark-id", default="custom", help="Benchmark identifier")
    parser.add_argument("--model", default=None, help="LLM model name")
    parser.add_argument("--api-key", default=None, help="LLM API key")
    parser.add_argument("--base-url", default=None, help="LLM API base URL")
    parser.add_argument("--out", default="", help="Output JSON path (default: <benchmark>/.benchmark_spec.json)")
    args = parser.parse_args()

    result = extract(
        args.path,
        benchmark_id=args.benchmark_id,
        model=args.model,
        api_key=args.api_key,
        base_url=args.base_url,
    )

    if args.out:
        Path(args.out).write_text(json.dumps(result, indent=2))
        print(f"Wrote to {args.out}")


if __name__ == "__main__":
    main()
