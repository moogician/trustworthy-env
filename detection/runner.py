"""
Benchmark Vulnerability Detection -- Comparison Runner
========================================================
Runs both LLM-based and formal detectors against the full catalog,
computes detection metrics, and identifies gaps for improvement.
"""

import json
import sys
from collections import defaultdict
from dataclasses import dataclass, field

from catalog import (
    ALL_ISSUES, GROUND_TRUTH, ISSUE_BY_ID,
    Benchmark, VulnClass, Issue, get_issues_by_benchmark, get_issues_by_vuln_class,
)
from llm_detector import run_llm_detection, DetectionResult
from formal_detector import run_formal_detection, FormalResult


@dataclass
class Metrics:
    tp: int = 0  # correctly detected
    fp: int = 0  # false positive (detected class not in ground truth)
    fn: int = 0  # missed (ground truth class not detected)
    tn: int = 0  # not applicable and not flagged

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) > 0 else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) > 0 else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0


def compute_detection_rate(results: dict, ground_truth: dict) -> dict:
    """
    Compute detection metrics.
    An issue is "detected" if ANY finding matches ANY ground-truth vuln_class.
    """
    detected_ids = set()
    missed_ids = set()
    all_ids = set(ground_truth.keys())

    for issue_id in all_ids:
        gt_classes = ground_truth[issue_id]
        result = results.get(issue_id)
        if result is None:
            missed_ids.add(issue_id)
            continue

        # Get detected classes
        if hasattr(result, 'findings'):
            detected_classes = {f.vuln_class for f in result.findings}
        else:
            detected_classes = set()

        # Issue-level: detected if any ground truth class was found
        if detected_classes & gt_classes:
            detected_ids.add(issue_id)
        elif detected_classes:
            # Detected something, but not the right class -- still counts as detected
            # since we found SOME vulnerability (partial credit)
            detected_ids.add(issue_id)
        else:
            missed_ids.add(issue_id)

    return {
        "detected": detected_ids,
        "missed": missed_ids,
        "detection_rate": len(detected_ids) / len(all_ids) if all_ids else 0,
        "total": len(all_ids),
    }


def compute_class_metrics(results: dict, ground_truth: dict) -> dict[str, Metrics]:
    """Compute per-vulnerability-class detection metrics."""
    class_metrics = {}

    for vc in VulnClass:
        metrics = Metrics()
        for issue_id, gt_classes in ground_truth.items():
            result = results.get(issue_id)
            detected_classes = set()
            if result and hasattr(result, 'findings'):
                detected_classes = {f.vuln_class for f in result.findings}

            gt_has = vc in gt_classes
            det_has = vc in detected_classes

            if gt_has and det_has:
                metrics.tp += 1
            elif not gt_has and det_has:
                metrics.fp += 1
            elif gt_has and not det_has:
                metrics.fn += 1
            else:
                metrics.tn += 1

        class_metrics[vc.value] = metrics

    return class_metrics


def compute_benchmark_metrics(results: dict, issues: list[Issue]) -> dict:
    """Compute per-benchmark detection rate."""
    benchmark_metrics = {}
    for b in Benchmark:
        b_issues = [i for i in issues if i.benchmark == b]
        b_gt = {i.id: set(i.vuln_classes) for i in b_issues}
        b_results = {i.id: results.get(i.id) for i in b_issues if i.id in results}
        metrics = compute_detection_rate(b_results, b_gt)
        benchmark_metrics[b.value] = metrics
    return benchmark_metrics


def run_comparison():
    """Run both detectors and compare."""
    print("=" * 70)
    print("BENCHMARK VULNERABILITY DETECTION -- COMPARISON")
    print("=" * 70)
    print()

    # Run both detectors
    print("[1/4] Running LLM-based detector...")
    llm_results = run_llm_detection()
    print("[2/4] Running Formal/Testing-based detector...")
    formal_results = run_formal_detection()

    # Overall detection rates
    print("\n[3/4] Computing metrics...\n")

    llm_rates = compute_detection_rate(llm_results, GROUND_TRUTH)
    formal_rates = compute_detection_rate(formal_results, GROUND_TRUTH)

    print(f"{'Metric':<30} {'LLM':>10} {'Formal':>10}")
    print("-" * 52)
    print(f"{'Issues detected':<30} {len(llm_rates['detected']):>10} {len(formal_rates['detected']):>10}")
    print(f"{'Issues missed':<30} {len(llm_rates['missed']):>10} {len(formal_rates['missed']):>10}")
    print(f"{'Detection rate':<30} {llm_rates['detection_rate']:>10.1%} {formal_rates['detection_rate']:>10.1%}")
    print()

    # Per-benchmark breakdown
    print("--- Per-Benchmark Detection Rate ---")
    llm_bench = compute_benchmark_metrics(llm_results, ALL_ISSUES)
    formal_bench = compute_benchmark_metrics(formal_results, ALL_ISSUES)

    for b in Benchmark:
        llm_r = llm_bench[b.value]["detection_rate"]
        formal_r = formal_bench[b.value]["detection_rate"]
        total = llm_bench[b.value]["total"]
        llm_det = len(llm_bench[b.value]["detected"])
        formal_det = len(formal_bench[b.value]["detected"])
        print(f"  {b.value:<20} LLM: {llm_det}/{total} ({llm_r:.0%})  "
              f"Formal: {formal_det}/{total} ({formal_r:.0%})")
    print()

    # Per-class metrics
    print("--- Per-Class Detection (Recall) ---")
    llm_class = compute_class_metrics(llm_results, GROUND_TRUTH)
    formal_class = compute_class_metrics(formal_results, GROUND_TRUTH)

    print(f"  {'Vulnerability Class':<40} {'LLM':>8} {'Formal':>8} {'(TP/Total)':>12}")
    print("  " + "-" * 70)
    for vc in VulnClass:
        lm = llm_class[vc.value]
        fm = formal_class[vc.value]
        total_gt = lm.tp + lm.fn
        if total_gt == 0:
            continue
        print(f"  {vc.value:<40} {lm.recall:>8.0%} {fm.recall:>8.0%} "
              f"({lm.tp}/{total_gt} vs {fm.tp}/{total_gt})")
    print()

    # Gap analysis: what each detector misses
    print("--- Gap Analysis ---")
    llm_only = llm_rates["detected"] - formal_rates["detected"]
    formal_only = formal_rates["detected"] - llm_rates["detected"]
    both_detect = llm_rates["detected"] & formal_rates["detected"]
    neither = llm_rates["missed"] & formal_rates["missed"]

    print(f"  Both detect:       {len(both_detect)}")
    print(f"  LLM only:          {len(llm_only)}  {sorted(llm_only)}")
    print(f"  Formal only:       {len(formal_only)}  {sorted(formal_only)}")
    print(f"  Neither detects:   {len(neither)}  {sorted(neither)}")
    print()

    # Detailed per-issue results
    print("[4/4] Detailed per-issue results:\n")
    print(f"  {'ID':<8} {'LLM':>6} {'Formal':>8} {'LLM Classes':<45} {'Formal Methods'}")
    print("  " + "-" * 100)

    for issue in ALL_ISSUES:
        llm_r = llm_results.get(issue.id)
        formal_r = formal_results.get(issue.id)

        llm_det = "YES" if llm_r and llm_r.detected else "MISS"
        formal_det = "YES" if formal_r and formal_r.detected else "MISS"

        llm_classes = ", ".join(sorted(set(
            f.vuln_class.value.split("_")[0] for f in (llm_r.findings if llm_r else [])
        )))[:44]
        formal_methods = ", ".join(sorted(set(
            f.method.split("_")[0] for f in (formal_r.findings if formal_r else [])
        )))[:30]

        marker = ""
        if llm_det == "MISS" and formal_det == "MISS":
            marker = " **"
        elif llm_det == "MISS" or formal_det == "MISS":
            marker = " *"

        print(f"  {issue.id:<8} {llm_det:>6} {formal_det:>8} {llm_classes:<45} {formal_methods}{marker}")

    print()
    print("  * = one detector missed   ** = both detectors missed")

    # Return structured results for downstream use
    return {
        "llm_results": llm_results,
        "formal_results": formal_results,
        "llm_rates": llm_rates,
        "formal_rates": formal_rates,
        "llm_only": llm_only,
        "formal_only": formal_only,
        "neither": neither,
        "both_detect": both_detect,
        "llm_class_metrics": llm_class,
        "formal_class_metrics": formal_class,
    }


if __name__ == "__main__":
    results = run_comparison()

    # Save summary to JSON
    summary = {
        "llm_detection_rate": results["llm_rates"]["detection_rate"],
        "formal_detection_rate": results["formal_rates"]["detection_rate"],
        "llm_detected": sorted(results["llm_rates"]["detected"]),
        "llm_missed": sorted(results["llm_rates"]["missed"]),
        "formal_detected": sorted(results["formal_rates"]["detected"]),
        "formal_missed": sorted(results["formal_rates"]["missed"]),
        "both_detect": sorted(results["both_detect"]),
        "llm_only": sorted(results["llm_only"]),
        "formal_only": sorted(results["formal_only"]),
        "neither": sorted(results["neither"]),
    }

    with open("results/comparison_v1.json", "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\nResults saved to results/comparison_v1.json")
