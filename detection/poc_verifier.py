"""PoC Verification Agent — confirms audit findings by synthesizing and executing real exploits.

Three-phase pipeline:
1. **RepoAnalyzer**: LLM agent explores the benchmark repo to build a structured profile
   (task descriptions, evaluators, entrypoints, execution model).
2. **Context-aware detection**: Findings are re-evaluated with full task context so the LLM
   can distinguish real exploits from domain-appropriate design (e.g., loose tolerances
   that are actually fine for the task).
3. **Agentic PoC synthesis**: For each plausible finding, an LLM agent crafts a malicious
   submission, runs it through the *real* benchmark entrypoint, and checks if it scores
   well despite not genuinely solving the task.

Usage:
    python detection/poc_verifier.py reports/FrontierCS-audit.json \\
        --benchmark-root frontiercs-scan \\
        --model vertex_ai/claude-opus-4-6 --api-key ... --base-url ...

Or via detect.py:
    python detect.py verify data/reports/FrontierCS-audit.json --model ... --api-key ... --base-url ...
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Data schemas
# ---------------------------------------------------------------------------

@dataclass
class TaskProfile:
    """Structured description of a single benchmark task/problem."""
    task_id: str
    description: str  # full problem statement
    evaluator_path: str  # path to evaluator script
    entrypoint_cmd: str  # how to run evaluation
    scoring_formula: str  # how score is computed
    correctness_check: str  # how correctness is verified
    submission_interface: str  # what a solution must implement
    execution_model: str  # "docker", "local_python", "docker-compose", etc.
    docker_image: str  # docker image if applicable
    tolerances: str  # rtol/atol values
    config: dict  # raw config.yaml if available


@dataclass
class BenchmarkProfile:
    """Full profile of a benchmark repository."""
    benchmark_id: str
    root_path: str
    summary: str  # high-level description
    execution_model: str  # how benchmarks are run
    tasks: list[TaskProfile]
    common_evaluator: str  # shared evaluator code if any
    entrypoint_pattern: str  # how to run a single task


@dataclass
class PoCResult:
    finding_id: str
    category: str
    severity: str
    title: str
    entity: str
    verdict: str  # "confirmed", "unconfirmed", "error", "skipped", "filtered"
    strategy: str  # what exploit strategy was attempted
    poc_code: str  # the crafted malicious submission
    execution_log: str  # full output from running through real benchmark
    score_achieved: float | None  # score the exploit got
    expected_score: str  # what score means exploitation worked
    explanation: str  # LLM's reasoning
    elapsed_s: float


@dataclass
class VerificationReport:
    source_report: str
    benchmark_id: str
    benchmark_profile: dict  # serialized BenchmarkProfile
    total_findings: int
    verified: int
    confirmed: int
    unconfirmed: int
    errored: int
    skipped: int
    filtered: int  # findings filtered out by context-aware review
    confirmation_rate: float
    results: list[PoCResult]


# ---------------------------------------------------------------------------
# Agent tool definitions for LLM function calling
# ---------------------------------------------------------------------------

AGENT_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read the contents of a file. Returns the text content.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Absolute or relative path to the file"},
                    "max_lines": {"type": "integer", "description": "Max lines to read (default 200)", "default": 200},
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "list_directory",
            "description": "List files and directories at a path. Returns names with type indicators.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Directory path to list"},
                    "recursive": {"type": "boolean", "description": "List recursively (default false)", "default": False},
                    "max_depth": {"type": "integer", "description": "Max recursion depth (default 2)", "default": 2},
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_files",
            "description": "Search for files matching a glob pattern or grep for content.",
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string", "description": "Glob pattern (e.g. '**/*.py') or grep regex"},
                    "path": {"type": "string", "description": "Base directory to search in"},
                    "mode": {"type": "string", "enum": ["glob", "grep"], "description": "Search mode", "default": "glob"},
                    "max_results": {"type": "integer", "description": "Max results to return", "default": 20},
                },
                "required": ["pattern", "path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "run_command",
            "description": "Execute a shell command and return stdout/stderr. Use for running benchmarks, docker, etc.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string", "description": "Shell command to execute"},
                    "cwd": {"type": "string", "description": "Working directory (default: benchmark root)"},
                    "timeout": {"type": "integer", "description": "Timeout in seconds (default 120)", "default": 120},
                },
                "required": ["command"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": "Write content to a file. Creates parent directories if needed.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Path to write to"},
                    "content": {"type": "string", "description": "File content to write"},
                },
                "required": ["path", "content"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "report_result",
            "description": "Report the final result of your investigation. Call this when done.",
            "parameters": {
                "type": "object",
                "properties": {
                    "verdict": {"type": "string", "enum": ["confirmed", "unconfirmed", "error"],
                                "description": "Whether the vulnerability is confirmed exploitable"},
                    "strategy": {"type": "string", "description": "The exploit strategy used"},
                    "poc_code": {"type": "string", "description": "The malicious submission code"},
                    "score_achieved": {"type": "number", "description": "Score the exploit achieved (null if not run)"},
                    "expected_score": {"type": "string", "description": "What score indicates success"},
                    "explanation": {"type": "string", "description": "Detailed explanation of findings"},
                },
                "required": ["verdict", "strategy", "explanation"],
            },
        },
    },
]


# ---------------------------------------------------------------------------
# Tool execution
# ---------------------------------------------------------------------------

def _exec_tool(name: str, args: dict, benchmark_root: str, work_dir: str) -> str:
    """Execute an agent tool and return the result as a string."""
    try:
        if name == "read_file":
            path = args["path"]
            max_lines = args.get("max_lines", 200)
            # Resolve relative paths against benchmark root
            if not os.path.isabs(path):
                candidates = [
                    os.path.join(benchmark_root, path),
                    os.path.join(work_dir, path),
                    path,
                ]
                for c in candidates:
                    if os.path.isfile(c):
                        path = c
                        break
            p = Path(path)
            if not p.is_file():
                return f"Error: File not found: {path}"
            if p.stat().st_size > 1_000_000:
                return f"Error: File too large ({p.stat().st_size} bytes)"
            lines = p.read_text(errors="replace").split("\n")
            content = "\n".join(lines[:max_lines])
            if len(lines) > max_lines:
                content += f"\n... ({len(lines) - max_lines} more lines)"
            return content

        elif name == "list_directory":
            path = args["path"]
            if not os.path.isabs(path):
                path = os.path.join(benchmark_root, path)
            recursive = args.get("recursive", False)
            max_depth = args.get("max_depth", 2)
            if not os.path.isdir(path):
                return f"Error: Directory not found: {path}"
            entries = []
            if recursive:
                for root, dirs, files in os.walk(path):
                    depth = root.replace(path, "").count(os.sep)
                    if depth >= max_depth:
                        dirs.clear()
                        continue
                    rel = os.path.relpath(root, path)
                    for f in sorted(files)[:50]:
                        entries.append(os.path.join(rel, f) if rel != "." else f)
                    if len(entries) > 200:
                        entries.append("... (truncated)")
                        break
            else:
                for item in sorted(os.listdir(path))[:100]:
                    full = os.path.join(path, item)
                    suffix = "/" if os.path.isdir(full) else ""
                    entries.append(item + suffix)
            return "\n".join(entries) if entries else "(empty directory)"

        elif name == "search_files":
            pattern = args["pattern"]
            path = args.get("path", benchmark_root)
            if not os.path.isabs(path):
                path = os.path.join(benchmark_root, path)
            mode = args.get("mode", "glob")
            max_results = args.get("max_results", 20)
            if mode == "glob":
                import glob as globmod
                results = sorted(globmod.glob(os.path.join(path, pattern), recursive=True))[:max_results]
                return "\n".join(os.path.relpath(r, benchmark_root) for r in results) if results else "(no matches)"
            else:  # grep
                try:
                    result = subprocess.run(
                        ["grep", "-rn", "--include=*.py", "--include=*.sh", "--include=*.yaml",
                         "--include=*.yml", "--include=*.json", "--include=*.md",
                         "-m", str(max_results), pattern, path],
                        capture_output=True, text=True, timeout=15
                    )
                    return result.stdout[:5000] if result.stdout else "(no matches)"
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    return "(search failed)"

        elif name == "run_command":
            command = args["command"]
            cwd = args.get("cwd", benchmark_root)
            if not os.path.isabs(cwd):
                cwd = os.path.join(benchmark_root, cwd)
            timeout = args.get("timeout", 120)

            # Safety: block obviously destructive commands
            dangerous = ["rm -rf /", "mkfs", "dd if=", "> /dev/"]
            if any(d in command for d in dangerous):
                return "Error: Command blocked for safety"

            result = subprocess.run(
                command, shell=True, capture_output=True, text=True,
                timeout=timeout, cwd=cwd,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            )
            output = result.stdout[-3000:] if len(result.stdout) > 3000 else result.stdout
            if result.stderr:
                output += "\n--- STDERR ---\n"
                output += result.stderr[-2000:] if len(result.stderr) > 2000 else result.stderr
            output += f"\n[exit code: {result.returncode}]"
            return output

        elif name == "write_file":
            path = args["path"]
            content = args["content"]
            # Only allow writing inside work_dir
            if not os.path.isabs(path):
                path = os.path.join(work_dir, path)
            p = Path(path)
            # Safety: must be inside work_dir or /tmp
            resolved = str(p.resolve())
            if not (resolved.startswith(work_dir) or resolved.startswith("/tmp")):
                return f"Error: Can only write files inside work directory ({work_dir}) or /tmp"
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
            return f"Wrote {len(content)} bytes to {path}"

        elif name == "report_result":
            return json.dumps(args)

        else:
            return f"Error: Unknown tool '{name}'"

    except subprocess.TimeoutExpired:
        return "Error: Command timed out"
    except Exception as e:
        return f"Error: {type(e).__name__}: {e}"


# ---------------------------------------------------------------------------
# LLM agent loop
# ---------------------------------------------------------------------------

def _run_agent_loop(
    llm_kwargs: dict,
    model: str,
    system_prompt: str,
    user_prompt: str,
    tools: list[dict],
    benchmark_root: str,
    work_dir: str,
    max_turns: int = 20,
    verbose: bool = False,
) -> dict:
    """Run an LLM agent loop with tool calling until report_result is called."""
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ]

    # Track state for salvage on timeout
    last_poc_code = ""
    last_run_output = ""
    last_text = ""

    for turn in range(max_turns):
        # Inject urgency warning when running low
        if turn == max_turns - 3:
            messages.append({
                "role": "user",
                "content": "WARNING: You have 2 turns left. Call report_result NOW with your findings so far.",
            })

        try:
            import litellm
            response = litellm.completion(
                model=model,
                max_tokens=4096,
                messages=messages,
                tools=tools,
                **llm_kwargs,
            )
        except Exception as e:
            return {"verdict": "error", "strategy": "", "explanation": f"LLM API error: {e}",
                    "poc_code": last_poc_code, "score_achieved": None, "expected_score": ""}

        choice = response.choices[0]
        msg = choice.message

        # No tool calls — agent is providing text (reasoning or final answer)
        if not msg.tool_calls:
            text = msg.content or ""
            last_text = text
            if verbose:
                print(f"    [agent turn {turn+1}] text: {text[:100]}")
            # Try to parse a verdict from text
            if "confirmed" in text.lower() and "unconfirmed" not in text.lower():
                return {"verdict": "confirmed", "strategy": "", "explanation": text[:500],
                        "poc_code": last_poc_code, "score_achieved": None, "expected_score": ""}
            if "unconfirmed" in text.lower():
                return {"verdict": "unconfirmed", "strategy": "", "explanation": text[:500],
                        "poc_code": last_poc_code, "score_achieved": None, "expected_score": ""}
            # If text but no verdict, continue (might be reasoning before tool call)
            messages.append(msg)
            continue

        # Process tool calls
        messages.append(msg)
        for tc in msg.tool_calls:
            fn_name = tc.function.name
            try:
                fn_args = json.loads(tc.function.arguments)
            except json.JSONDecodeError:
                fn_args = {}

            if verbose:
                args_summary = str(fn_args)[:80]
                print(f"    [agent turn {turn+1}] {fn_name}({args_summary})")

            # Track write_file and run_command for salvage
            if fn_name == "write_file" and fn_args.get("content", ""):
                content = fn_args["content"]
                # Keep the most recent solution/exploit file
                if any(kw in fn_args.get("path", "").lower()
                       for kw in ("solution", "exploit", "poc", "hack", "malicious")):
                    last_poc_code = content
            if fn_name == "run_command":
                pass  # output captured below

            # Execute tool
            result_str = _exec_tool(fn_name, fn_args, benchmark_root, work_dir)

            # Track run outputs for salvage
            if fn_name == "run_command":
                last_run_output = result_str

            # Check for report_result — we're done
            if fn_name == "report_result":
                # Merge any tracked poc_code if not in args
                if not fn_args.get("poc_code") and last_poc_code:
                    fn_args["poc_code"] = last_poc_code
                return fn_args

            messages.append({
                "role": "tool",
                "tool_call_id": tc.id,
                "content": result_str[:8000],
            })

    # Salvage: construct a partial result from what we tracked
    explanation = f"Agent used all {max_turns} turns. "
    if last_text:
        explanation += f"Last reasoning: {last_text[:300]}"
    elif last_run_output:
        explanation += f"Last command output: {last_run_output[:300]}"

    # Determine verdict from tracked outputs
    verdict = "error"
    combined = (last_run_output + " " + last_text).lower()
    if "confirmed" in combined and "unconfirmed" not in combined:
        verdict = "confirmed"
    elif "unconfirmed" in combined:
        verdict = "unconfirmed"
    elif last_poc_code and last_run_output:
        # Agent wrote and ran code — this is a partial result, not a total failure
        verdict = "unconfirmed"
        explanation = f"Agent ran out of turns but wrote and executed exploit code. Last output: {last_run_output[:300]}"

    return {"verdict": verdict, "strategy": "partial (turn limit)",
            "explanation": explanation,
            "poc_code": last_poc_code, "score_achieved": None, "expected_score": "",
            "execution_log": last_run_output[:2000]}


# ---------------------------------------------------------------------------
# Phase 1: Repository analysis
# ---------------------------------------------------------------------------

_REPO_ANALYZER_SYSTEM = """\
You are a benchmark analysis agent. Your job is to explore a benchmark \
repository and build a structured understanding of how it works.

You have tools to read files, list directories, and search. Use them to find:
1. What problems/tasks does this benchmark contain?
2. For each task: what is the problem description, evaluator, scoring formula?
3. How are solutions submitted and evaluated? (Docker, local script, etc.)
4. What is the entrypoint command to run evaluation?
5. What correctness checks and tolerances are used?

When done, call report_result with a JSON summary."""

_REPO_ANALYZER_USER = """\
Explore the benchmark repository at: {benchmark_root}

Build a complete profile. Follow this plan EFFICIENTLY — you have limited turns:

STEP 1: List the top-level directory to understand structure.
STEP 2: Read the README or SUBMIT.md if present.
STEP 3: Find and read ONE evaluator/scoring script (look in src/, eval/, scoring/, or similar).
STEP 4: Find and read the benchmark.py or scoring code for that same problem.
STEP 5: Read the config.yaml or similar config for that problem.
STEP 6: Call report_result immediately.

Do NOT try to read every file. Read 3-5 files total, then report.

Call report_result with a JSON object containing:
{{
  "summary": "high-level description of what this benchmark tests",
  "execution_model": "docker|local_python|docker-compose",
  "entrypoint_pattern": "command to run one problem, e.g. python3 evaluator.py --solution-path X",
  "tasks": [
    {{
      "task_id": "problem name",
      "description": "what the task asks (2-3 sentences)",
      "evaluator_path": "relative path to evaluator.py",
      "scoring_formula": "how score is computed",
      "correctness_check": "how correctness is verified (tolerances, etc.)",
      "submission_interface": "what function/class a solution must define",
      "docker_image": "image name if applicable",
      "tolerances": "rtol and atol values"
    }}
  ]
}}

Include 3-5 representative tasks. Call report_result by turn 10 at the latest."""


def analyze_repo(
    llm_kwargs: dict, model: str, benchmark_root: str, verbose: bool = False
) -> BenchmarkProfile:
    """Use an LLM agent to explore and profile a benchmark repository."""
    print("[repo-analyzer] Exploring benchmark repository...")

    work_dir = tempfile.mkdtemp(prefix="repo_analyze_")
    try:
        # Tools for repo analysis (no write_file or run_command needed)
        analysis_tools = [t for t in AGENT_TOOLS if t["function"]["name"] in
                          ("read_file", "list_directory", "search_files", "report_result")]

        result = _run_agent_loop(
            llm_kwargs=llm_kwargs, model=model,
            system_prompt=_REPO_ANALYZER_SYSTEM,
            user_prompt=_REPO_ANALYZER_USER.format(benchmark_root=benchmark_root),
            tools=analysis_tools,
            benchmark_root=benchmark_root,
            work_dir=work_dir,
            max_turns=15,
            verbose=verbose,
        )
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)

    # Parse the result into a BenchmarkProfile
    tasks = []
    raw_tasks = result.get("tasks", [])
    if isinstance(raw_tasks, str):
        try:
            raw_tasks = json.loads(raw_tasks)
        except json.JSONDecodeError:
            raw_tasks = []

    for t in raw_tasks:
        if isinstance(t, dict):
            tasks.append(TaskProfile(
                task_id=t.get("task_id", "unknown"),
                description=t.get("description", ""),
                evaluator_path=t.get("evaluator_path", ""),
                entrypoint_cmd=t.get("entrypoint_cmd", ""),
                scoring_formula=t.get("scoring_formula", ""),
                correctness_check=t.get("correctness_check", ""),
                submission_interface=t.get("submission_interface", ""),
                execution_model=t.get("execution_model", result.get("execution_model", "")),
                docker_image=t.get("docker_image", ""),
                tolerances=t.get("tolerances", ""),
                config=t.get("config", {}),
            ))

    profile = BenchmarkProfile(
        benchmark_id=os.path.basename(benchmark_root.rstrip("/")),
        root_path=benchmark_root,
        summary=result.get("summary", result.get("explanation", "")),
        execution_model=result.get("execution_model", "unknown"),
        tasks=tasks,
        common_evaluator=result.get("common_evaluator", ""),
        entrypoint_pattern=result.get("entrypoint_pattern", ""),
    )

    print(f"[repo-analyzer] Found {len(tasks)} tasks, execution model: {profile.execution_model}")
    for t in tasks[:5]:
        print(f"  - {t.task_id}: {t.description[:80]}...")

    return profile


# ---------------------------------------------------------------------------
# Phase 2: Context-aware finding filter
# ---------------------------------------------------------------------------

_FILTER_SYSTEM = """\
You are a security auditor reviewing benchmark vulnerability findings. \
You have full context on the benchmark's tasks, scoring, and design.

Your job is to AGGRESSIVELY filter findings. Default to REJECTING unless \
you see a clear, concrete exploit path. Most automated findings are noise.

REJECT if ANY of these apply:
- The finding is SPECULATIVE ("may", "could", "if an attacker...") without \
  a concrete code path that proves exploitability.
- It describes a DESIGN CHOICE, not a bug (e.g., using subprocess, loading \
  files from disk, trusting model output in an inference script).
- It flags missing validation in TRUSTED INTERNAL code (evaluator scripts \
  are not user-facing APIs — they don't need input sanitization).
- It's about "data contamination" or "missing dependency" — these are meta \
  concerns, not exploitable code vulnerabilities.
- It's about "safety concern" for standard benchmark operations (network, \
  subprocess, file I/O).
- It's about environment variables, API keys, or configuration — these are \
  operational, not scoring vulnerabilities.
- The "exploit" requires replacing benchmark infrastructure files that would \
  be detected by any integrity check or wouldn't survive a fresh clone.
- A "loose tolerance" is appropriate for the domain (e.g., FP16 GPU computation).
- Division by zero in trusted evaluator code with controlled inputs is NOT a bug.

KEEP only findings where:
- There is a CONCRETE, SPECIFIC code path an adversarial submission can trigger \
  to get a high score WITHOUT solving the task.
- The exploit works WITHIN the normal submission interface (not by modifying \
  benchmark infrastructure).
- You can describe the exact exploit in one sentence."""

_FILTER_USER = """\
## Benchmark Context
{benchmark_summary}

## Task Descriptions
{task_descriptions}

## Findings to Review
{findings_json}

For each finding, respond with a JSON array where each entry has:
- "finding_id": the original finding ID
- "keep": true if this is a REAL exploitable vulnerability, false if it's a false positive
- "reason": one sentence explaining why

Be VERY strict — reject questionable findings. Only keep findings where \
you can describe a concrete exploit that an adversarial submission could use to \
get a high score without genuinely solving the task. When in doubt, reject."""


def filter_findings_with_context(
    llm_kwargs: dict, model: str, findings: list[dict],
    profile: BenchmarkProfile, verbose: bool = False,
) -> list[dict]:
    """Use LLM to filter findings using benchmark context. Returns kept findings."""
    if not findings:
        return []

    # Build task descriptions string
    task_descs = []
    for t in profile.tasks:
        task_descs.append(
            f"**{t.task_id}**: {t.description}\n"
            f"  Scoring: {t.scoring_formula}\n"
            f"  Correctness: {t.correctness_check}\n"
            f"  Tolerances: {t.tolerances}"
        )
    task_str = "\n\n".join(task_descs) if task_descs else "(no task descriptions available)"

    # Process in batches of 20
    kept = []
    batch_size = 20
    for i in range(0, len(findings), batch_size):
        batch = findings[i:i + batch_size]
        # Slim down findings for the prompt
        slim = [{
            "finding_id": f["finding_id"],
            "category": f["category"],
            "severity": f["severity"],
            "title": f["title"],
            "entity": f.get("entity", ""),
            "evidence": f.get("evidence", "")[:300],
        } for f in batch]

        prompt = _FILTER_USER.format(
            benchmark_summary=profile.summary[:2000],
            task_descriptions=task_str[:4000],
            findings_json=json.dumps(slim, indent=2),
        )

        try:
            import litellm
            response = litellm.completion(
                model=model,
                max_tokens=4096,
                messages=[
                    {"role": "system", "content": _FILTER_SYSTEM},
                    {"role": "user", "content": prompt},
                ],
                **llm_kwargs,
            )
            text = response.choices[0].message.content

            # Parse JSON response
            json_str = text.strip()
            if "```" in json_str:
                match = re.search(r"```(?:json)?\s*\n?(.*?)```", json_str, re.S)
                if match:
                    json_str = match.group(1).strip()
            items = json.loads(json_str)

            keep_ids = {item["finding_id"] for item in items if item.get("keep")}
            for f in batch:
                if f["finding_id"] in keep_ids:
                    kept.append(f)

            if verbose:
                filtered_count = len(batch) - len(keep_ids)
                print(f"  [filter] Batch {i//batch_size + 1}: kept {len(keep_ids)}/{len(batch)}, "
                      f"filtered {filtered_count} false positives")
        except Exception as e:
            if verbose:
                print(f"  [filter] Batch {i//batch_size + 1} error: {e}, keeping all")
            kept.extend(batch)

    return kept


# ---------------------------------------------------------------------------
# Phase 3: Agentic PoC verification
# ---------------------------------------------------------------------------

_POC_AGENT_SYSTEM = """\
You are a security researcher evaluating whether a reported benchmark \
vulnerability is REAL and EXPLOITABLE.

CRITICAL: EARLY REJECTION. After reading the evaluator code (turns 1-2), \
make a quick judgment: is this vulnerability actually exploitable given how \
the benchmark works? If NOT, call report_result immediately with verdict \
"unconfirmed" and save everyone's time. Do NOT spend turns trying to build \
an exploit for a finding that is clearly a false positive.

Reject early if:
- The finding describes a theoretical concern but the actual code handles it
- The "vulnerability" requires modifying benchmark infrastructure (not the submission)
- The exploit would be caught by existing checks in the evaluation pipeline
- The finding is about missing validation in trusted internal code
- The evaluator runs in a separate process/container from the submission

If the vulnerability IS promising after reading the code, then proceed:

You have tools to:
- Read the evaluator source code and understand exactly how scoring works
- Write a crafted solution file
- Run the evaluation through the real benchmark entrypoint
- Inspect the output/score

Exploit strategies (only if vulnerability is real):
- Monkey-patch the evaluator's scoring function at import time
- Overwrite reference/baseline files to make comparison trivial
- Inject fake scores via stdout (if score is parsed from output)
- Return the baseline implementation itself (if accessible)
- Exploit loose tolerances by returning approximate/cached results

If GPU/Docker is unavailable, demonstrate the exploit statically by showing \
the vulnerable code path with a concrete exploit that would trigger it.

You MUST call report_result by turn 12. Budget: 1-2 turns reading code, \
then either reject early OR spend 2-3 turns on exploit + 1 turn reporting."""

_POC_AGENT_USER = """\
## Vulnerability Finding
- **ID**: {finding_id}
- **Category**: {category}
- **Severity**: {severity}
- **Title**: {title}
- **Evidence**: {evidence}

## Benchmark Context
{benchmark_summary}

## Task Context
{task_description}
- **Evaluator**: {evaluator_path}
- **Scoring**: {scoring_formula}
- **Correctness**: {correctness_check}
- **Submission interface**: {submission_interface}
- **Entrypoint**: {entrypoint_cmd}
- **Tolerances**: {tolerances}

## Benchmark Root
{benchmark_root}

## Work Directory (write files here)
{work_dir}

## Instructions
Follow this plan — you have LIMITED TURNS, be efficient:

STEP 1 (turns 1-3): Read the evaluator code and benchmark.py to understand \
the exact scoring and correctness checking logic.

STEP 2 (turns 4-5): Design an exploit. Write a malicious solution.py to \
the work directory that exploits the vulnerability.

STEP 3 (turns 6-8): Try to run the exploit through the real evaluation:
   python3 <evaluator_path> --solution-path <your_exploit.py> --output-path result.json
   If it needs GPU/Docker, try running with mock/CPU fallback, or demonstrate \
   the exploit statically by showing the code path that would be exploited.

STEP 4 (turn 9+): Call report_result with your verdict. Include the exploit \
code in poc_code, the score in score_achieved, and a clear explanation.

A finding is CONFIRMED if:
- The exploit gets score > 0 without genuinely solving the task, OR
- You can demonstrate (by reading the code) that a specific code path allows \
  score manipulation, with a concrete exploit that would trigger it.

A finding is UNCONFIRMED if the evaluator's checks would catch the exploit."""


class PoCVerifier:
    """Agentic PoC verification pipeline."""

    def __init__(
        self,
        model: str | None = None,
        api_key: str | None = None,
        base_url: str | None = None,
        timeout_s: int = 120,
        max_findings: int | None = None,
        max_agent_turns: int = 20,
        verbose: bool = False,
        skip_analysis: bool = False,
        benchmark_root: str | None = None,
    ) -> None:
        self._model = model or os.environ.get("AUDIT_MODEL") or "gpt-4o-mini"
        self._api_key = api_key or os.environ.get("AUDIT_API_KEY") or os.environ.get("MODEL_API_KEY")
        self._base_url = base_url or os.environ.get("AUDIT_BASE_URL")
        self._timeout_s = timeout_s
        self._max_findings = max_findings
        self._max_agent_turns = max_agent_turns
        self._verbose = verbose
        self._skip_analysis = skip_analysis
        self._benchmark_root_override = benchmark_root

        if not self._api_key:
            for env_var in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY"):
                val = os.environ.get(env_var)
                if val:
                    self._api_key = val
                    break

    @property
    def _llm_kwargs(self) -> dict:
        kwargs: dict[str, Any] = {}
        if self._api_key:
            kwargs["api_key"] = self._api_key
        if self._base_url:
            kwargs["api_base"] = self._base_url
        return kwargs

    @property
    def available(self) -> bool:
        return bool(self._api_key)

    # ------------------------------------------------------------------
    # Main pipeline
    # ------------------------------------------------------------------

    def verify_report(self, report_path: str) -> VerificationReport:
        """Full pipeline: analyze repo -> filter findings -> generate PoCs."""
        with open(report_path) as f:
            report_data = json.load(f)

        benchmark_id = report_data.get("benchmark_spec", {}).get("benchmark_id", "unknown")
        benchmark_root = self._benchmark_root_override or report_data.get("benchmark_spec", {}).get("root_path", "")

        # Make benchmark_root absolute
        if benchmark_root and not os.path.isabs(benchmark_root):
            benchmark_root = os.path.abspath(benchmark_root)

        findings = report_data.get("findings", [])

        if not self._api_key:
            print("[poc-verifier] ERROR: LLM API key required for agentic verification")
            print("[poc-verifier] Provide --model, --api-key, and --base-url")
            return self._empty_report(report_path, benchmark_id, findings)

        # Phase 1: Analyze the repository
        print("=" * 60)
        print("PHASE 1: Repository Analysis")
        print("=" * 60)
        if self._skip_analysis:
            profile = BenchmarkProfile(
                benchmark_id=benchmark_id, root_path=benchmark_root,
                summary="(analysis skipped)", execution_model="unknown",
                tasks=[], common_evaluator="", entrypoint_pattern="",
            )
        else:
            profile = analyze_repo(
                self._llm_kwargs, self._model, benchmark_root, self._verbose
            )
        print()

        # Phase 2: Context-aware filtering
        print("=" * 60)
        print("PHASE 2: Context-Aware Finding Filter")
        print("=" * 60)

        # Deduplicate findings by (category, entity)
        seen: dict[tuple[str, str], dict] = {}
        severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        for f in findings:
            key = (f["category"], f.get("entity", ""))
            existing = seen.get(key)
            if not existing or severity_rank.get(f["severity"], 4) < severity_rank.get(existing["severity"], 4):
                seen[key] = f
        deduped = list(seen.values())
        deduped.sort(key=lambda f: severity_rank.get(f["severity"], 4))

        print(f"[filter] {len(findings)} findings -> {len(deduped)} after dedup")

        kept = filter_findings_with_context(
            self._llm_kwargs, self._model, deduped, profile, self._verbose
        )
        filtered_count = len(deduped) - len(kept)
        print(f"[filter] {len(kept)} kept, {filtered_count} filtered as false positives")
        print()

        # Per-category sampling: verify up to N representatives per category
        # to avoid running 50 agents on the same vulnerability class
        MAX_PER_CATEGORY = 3
        from collections import defaultdict
        cat_counts: dict[str, int] = defaultdict(int)
        sampled = []
        deferred = []  # kept but not verified (same class, already sampled)
        for f in kept:
            cat = f["category"]
            if cat_counts[cat] < MAX_PER_CATEGORY:
                sampled.append(f)
                cat_counts[cat] += 1
            else:
                deferred.append(f)

        print(f"[sample] {len(kept)} kept -> {len(sampled)} sampled for verification "
              f"({len(deferred)} deferred, same vuln class already covered)")

        if self._max_findings:
            sampled = sampled[:self._max_findings]

        # Phase 3: Agentic PoC verification
        print("=" * 60)
        print("PHASE 3: Agentic PoC Verification")
        print("=" * 60)

        results: list[PoCResult] = []
        filtered_ids = set(f["finding_id"] for f in deduped) - set(f["finding_id"] for f in kept)
        deferred_ids = set(f["finding_id"] for f in deferred)

        # Add filtered and deferred findings to results
        for f in deduped:
            if f["finding_id"] in filtered_ids:
                results.append(PoCResult(
                    finding_id=f["finding_id"], category=f["category"],
                    severity=f["severity"], title=f["title"],
                    entity=f.get("entity", ""), verdict="filtered",
                    strategy="", poc_code="", execution_log="",
                    score_achieved=None, expected_score="",
                    explanation="Filtered as false positive by context-aware review",
                    elapsed_s=0,
                ))
            elif f["finding_id"] in deferred_ids:
                results.append(PoCResult(
                    finding_id=f["finding_id"], category=f["category"],
                    severity=f["severity"], title=f["title"],
                    entity=f.get("entity", ""), verdict="skipped",
                    strategy="", poc_code="", execution_log="",
                    score_achieved=None, expected_score="",
                    explanation=f"Same vulnerability class '{f['category']}' already verified on another entity",
                    elapsed_s=0,
                ))

        for i, finding in enumerate(sampled):
            fid = finding.get("finding_id", "")
            title = finding.get("title", "")
            category = finding.get("category", "")
            print(f"\n  [{i+1}/{len(sampled)}] {fid} ({category}): {title[:60]}...")

            result = self._verify_single_agentic(finding, profile, benchmark_root)
            results.append(result)

            icon = {"confirmed": "CONFIRMED", "unconfirmed": "UNCONFIRMED", "error": "ERROR"}.get(result.verdict, "???")
            print(f"           -> {icon} ({result.elapsed_s:.1f}s)")
            if result.score_achieved is not None:
                print(f"              Score achieved: {result.score_achieved}")
            if result.strategy:
                print(f"              Strategy: {result.strategy[:80]}")

        confirmed = sum(1 for r in results if r.verdict == "confirmed")
        unconfirmed = sum(1 for r in results if r.verdict == "unconfirmed")
        errored = sum(1 for r in results if r.verdict == "error")
        skipped = sum(1 for r in results if r.verdict == "skipped")
        filtered_total = sum(1 for r in results if r.verdict == "filtered")
        verified = confirmed + unconfirmed
        rate = confirmed / verified if verified > 0 else 0.0

        print()
        print("=" * 60)
        print(f"RESULTS: {confirmed} confirmed, {unconfirmed} unconfirmed, "
              f"{errored} errors, {filtered_total} filtered, {skipped} skipped")
        print(f"Confirmation rate (of verified): {rate:.1%}")
        print("=" * 60)

        return VerificationReport(
            source_report=report_path,
            benchmark_id=benchmark_id,
            benchmark_profile=asdict(profile),
            total_findings=len(findings),
            verified=verified,
            confirmed=confirmed,
            unconfirmed=unconfirmed,
            errored=errored,
            skipped=skipped,
            filtered=filtered_total,
            confirmation_rate=rate,
            results=results,
        )

    # ------------------------------------------------------------------
    # Single finding: agentic verification
    # ------------------------------------------------------------------

    def _verify_single_agentic(
        self, finding: dict, profile: BenchmarkProfile, benchmark_root: str,
    ) -> PoCResult:
        t0 = time.time()
        fid = finding.get("finding_id", "")
        category = finding.get("category", "")
        severity = finding.get("severity", "")
        title = finding.get("title", "")
        entity = finding.get("entity", "")
        evidence = finding.get("evidence", "")

        # Find matching task profile
        task = self._find_matching_task(entity, profile)
        task_desc = (
            f"Task: {task.task_id}\n{task.description}\n"
            f"Evaluator: {task.evaluator_path}\n"
            f"Scoring: {task.scoring_formula}\n"
            f"Correctness: {task.correctness_check}"
            if task else "(no specific task matched)"
        )

        # Create isolated work directory
        work_dir = tempfile.mkdtemp(prefix=f"poc_{fid}_")

        try:
            prompt = _POC_AGENT_USER.format(
                finding_id=fid, category=category, severity=severity,
                title=title, evidence=evidence,
                benchmark_summary=profile.summary[:1500],
                task_description=task_desc,
                evaluator_path=task.evaluator_path if task else entity,
                scoring_formula=task.scoring_formula if task else "(unknown)",
                correctness_check=task.correctness_check if task else "(unknown)",
                submission_interface=task.submission_interface if task else "(unknown)",
                entrypoint_cmd=task.entrypoint_cmd if task else profile.entrypoint_pattern,
                tolerances=task.tolerances if task else "(unknown)",
                benchmark_root=benchmark_root,
                work_dir=work_dir,
            )

            agent_result = _run_agent_loop(
                llm_kwargs=self._llm_kwargs,
                model=self._model,
                system_prompt=_POC_AGENT_SYSTEM,
                user_prompt=prompt,
                tools=AGENT_TOOLS,
                benchmark_root=benchmark_root,
                work_dir=work_dir,
                max_turns=self._max_agent_turns,
                verbose=self._verbose,
            )

            return PoCResult(
                finding_id=fid, category=category, severity=severity,
                title=title, entity=entity,
                verdict=agent_result.get("verdict", "error"),
                strategy=agent_result.get("strategy", ""),
                poc_code=agent_result.get("poc_code", ""),
                execution_log=agent_result.get("execution_log", ""),
                score_achieved=agent_result.get("score_achieved"),
                expected_score=agent_result.get("expected_score", ""),
                explanation=agent_result.get("explanation", ""),
                elapsed_s=time.time() - t0,
            )

        except Exception as e:
            return PoCResult(
                finding_id=fid, category=category, severity=severity,
                title=title, entity=entity, verdict="error",
                strategy="", poc_code="", execution_log=str(e),
                score_achieved=None, expected_score="",
                explanation=f"Exception during verification: {e}",
                elapsed_s=time.time() - t0,
            )
        finally:
            shutil.rmtree(work_dir, ignore_errors=True)

    def _find_matching_task(self, entity: str, profile: BenchmarkProfile) -> TaskProfile | None:
        """Find the task profile that best matches a finding's entity path."""
        if not profile.tasks:
            return None

        entity_lower = entity.lower()
        best = None
        best_score = 0
        for task in profile.tasks:
            score = 0
            tid = task.task_id.lower()
            # Check if task ID appears in entity path
            if tid in entity_lower:
                score += 10
            # Check if evaluator path overlaps
            if task.evaluator_path and task.evaluator_path.lower() in entity_lower:
                score += 5
            # Partial path matching
            for part in tid.split("/"):
                if part and part in entity_lower:
                    score += 3
            if score > best_score:
                best_score = score
                best = task

        return best or (profile.tasks[0] if profile.tasks else None)

    def _empty_report(self, report_path: str, benchmark_id: str, findings: list) -> VerificationReport:
        return VerificationReport(
            source_report=report_path, benchmark_id=benchmark_id,
            benchmark_profile={}, total_findings=len(findings),
            verified=0, confirmed=0, unconfirmed=0, errored=0, skipped=0, filtered=0,
            confirmation_rate=0.0, results=[],
        )


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

def write_verification_report(report: VerificationReport, out_path: str) -> None:
    """Write verification results as JSON."""
    data = {
        "source_report": report.source_report,
        "benchmark_id": report.benchmark_id,
        "benchmark_profile": report.benchmark_profile,
        "total_findings": report.total_findings,
        "verified": report.verified,
        "confirmed": report.confirmed,
        "unconfirmed": report.unconfirmed,
        "errored": report.errored,
        "skipped": report.skipped,
        "filtered": report.filtered,
        "confirmation_rate": round(report.confirmation_rate, 4),
        "results": [asdict(r) for r in report.results],
    }
    with open(out_path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[poc-verifier] Wrote {out_path}")


def write_verification_markdown(report: VerificationReport, out_path: str) -> None:
    """Write a human-readable markdown verification report."""
    lines: list[str] = []
    lines.append(f"# PoC Verification Report: {report.benchmark_id}")
    lines.append("")
    lines.append(f"**Source**: `{report.source_report}`")
    lines.append(f"**Total findings**: {report.total_findings}")
    lines.append(f"**Filtered (false positives)**: {report.filtered}")
    lines.append(f"**Verified**: {report.verified}")
    lines.append(f"**Confirmed exploitable**: {report.confirmed}")
    lines.append(f"**Unconfirmed**: {report.unconfirmed}")
    lines.append(f"**Errors**: {report.errored}")
    lines.append(f"**Confirmation rate**: {report.confirmation_rate:.1%}")
    lines.append("")

    # Confirmed findings
    confirmed = [r for r in report.results if r.verdict == "confirmed"]
    if confirmed:
        lines.append("## Confirmed Exploits")
        lines.append("")
        for r in confirmed:
            lines.append(f"### {r.finding_id} — {r.title}")
            lines.append(f"- **Category**: `{r.category}` | **Severity**: {r.severity}")
            lines.append(f"- **Entity**: `{r.entity}`")
            lines.append(f"- **Strategy**: {r.strategy}")
            if r.score_achieved is not None:
                lines.append(f"- **Score achieved**: {r.score_achieved}")
            lines.append(f"- **Explanation**: {r.explanation}")
            lines.append("")
            if r.poc_code:
                lines.append("<details><summary>Exploit Code</summary>")
                lines.append("")
                lines.append("```python")
                lines.append(r.poc_code)
                lines.append("```")
                lines.append("</details>")
                lines.append("")
            if r.execution_log:
                lines.append("<details><summary>Execution Log</summary>")
                lines.append("")
                lines.append("```")
                lines.append(r.execution_log[:3000])
                lines.append("```")
                lines.append("</details>")
                lines.append("")

    # Unconfirmed findings
    unconfirmed = [r for r in report.results if r.verdict == "unconfirmed"]
    if unconfirmed:
        lines.append("## Unconfirmed Findings")
        lines.append("")
        for r in unconfirmed:
            lines.append(f"- **{r.finding_id}** (`{r.category}`, {r.severity}): {r.title}")
            lines.append(f"  - Strategy attempted: {r.strategy or 'N/A'}")
            lines.append(f"  - Reason: {r.explanation[:200]}")
        lines.append("")

    # Filtered findings
    filtered = [r for r in report.results if r.verdict == "filtered"]
    if filtered:
        lines.append("## Filtered as False Positives")
        lines.append("")
        for r in filtered:
            lines.append(f"- **{r.finding_id}** (`{r.category}`): {r.title}")
        lines.append("")

    # Errors
    errors = [r for r in report.results if r.verdict == "error"]
    if errors:
        lines.append("## Verification Errors")
        lines.append("")
        for r in errors:
            lines.append(f"- **{r.finding_id}** (`{r.category}`): {r.explanation[:200]}")
        lines.append("")

    with open(out_path, "w") as f:
        f.write("\n".join(lines))
    print(f"[poc-verifier] Wrote {out_path}")


# ---------------------------------------------------------------------------
# Standalone CLI
# ---------------------------------------------------------------------------

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="Agentic PoC Verification — confirm audit findings with real exploits"
    )
    parser.add_argument("report", help="Path to audit JSON report")
    parser.add_argument("--benchmark-root", default=None, help="Override benchmark root path")
    parser.add_argument("--out-json", default="", help="Write JSON verification report")
    parser.add_argument("--out-md", default="", help="Write markdown verification report")
    parser.add_argument("--model", default=None, help="LLM model name")
    parser.add_argument("--api-key", default=None, help="LLM API key")
    parser.add_argument("--base-url", default=None, help="LLM API base URL")
    parser.add_argument("--timeout-s", type=int, default=120, help="PoC execution timeout")
    parser.add_argument("--max-findings", type=int, default=None, help="Max findings to verify")
    parser.add_argument("--max-agent-turns", type=int, default=15, help="Max agent turns per finding")
    parser.add_argument("--skip-analysis", action="store_true", help="Skip repo analysis phase")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output (show agent actions)")

    args = parser.parse_args()

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
        print("[poc-verifier] ERROR: LLM client is required for agentic verification.")
        print("[poc-verifier] Provide --model, --api-key, and --base-url flags.")
        sys.exit(1)

    report = verifier.verify_report(args.report)

    # Default output paths
    base = os.path.splitext(os.path.basename(args.report))[0]
    out_dir = os.path.dirname(args.report) or "."

    json_path = args.out_json or os.path.join(out_dir, f"{base}-verified.json")
    md_path = args.out_md or os.path.join(out_dir, f"{base}-verified.md")

    write_verification_report(report, json_path)
    write_verification_markdown(report, md_path)


if __name__ == "__main__":
    main()
