#!/usr/bin/env python3
"""
CI hook for benchmark regression detection.

Runs the full benchmark suite, compares against a baseline report,
and exits non-zero if any metric regresses beyond tolerance.

Usage:
    python benchmarks/ci_hook.py --baseline benchmarks/results/baseline_report.json

Regression thresholds:
- AUC-PR drop > 0.02
- Detection rate drop > 0.05 on any scenario
- Alert volume increase > 20%
- Inference latency p95 increase > 50%

MITRE ATT&CK: validates detection coverage across all technique IDs.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from benchmarks.evaluate import (
    BenchmarkReport,
    JobMetrics,
    PipelineBenchmark,
    ScenarioMetrics,
)

logger = logging.getLogger(__name__)

LATENCY_P95_TOLERANCE: float = 1.50  # 50% increase


def _load_baseline(path: Path) -> BenchmarkReport:
    """Load a baseline benchmark report from JSON.

    Args:
        path: Path to baseline JSON file.

    Returns:
        Reconstructed BenchmarkReport.
    """
    data = json.loads(path.read_text())
    report = BenchmarkReport(
        overall_auc_pr=data.get("overall_auc_pr", 0.0),
        overall_auc_roc=data.get("overall_auc_roc", 0.0),
        mean_time_to_detect_minutes=data.get("mean_time_to_detect_minutes", 0.0),
        alerts_per_day=data.get("alerts_per_day", 0.0),
        timestamp=data.get("timestamp", ""),
        pipeline_config_hash=data.get("pipeline_config_hash", ""),
    )
    for name, sd in data.get("per_scenario", {}).items():
        report.per_scenario[name] = ScenarioMetrics(
            scenario_name=sd["scenario_name"],
            attack_events_total=sd.get("attack_events_total", 0),
            attack_events_detected=sd.get("attack_events_detected", 0),
            detection_rate=sd.get("detection_rate", 0.0),
            false_alarms=sd.get("false_alarms", 0),
            precision=sd.get("precision", 0.0),
            f1=sd.get("f1", 0.0),
            time_to_first_detection_sec=sd.get("time_to_first_detection_sec", 0.0),
            kill_chain_phases_detected=sd.get("kill_chain_phases_detected", []),
            kill_chain_completeness=sd.get("kill_chain_completeness", 0.0),
        )
    for name, jd in data.get("per_job", {}).items():
        report.per_job[name] = JobMetrics(
            job_name=jd["job_name"],
            events_scored=jd.get("events_scored", 0),
            anomalies_flagged=jd.get("anomalies_flagged", 0),
            mean_score=jd.get("mean_score", 0.0),
            max_score=jd.get("max_score", 0.0),
            scoring_time_ms=jd.get("scoring_time_ms", 0.0),
        )
    return report


def _check_latency_regression(
    baseline_perf: dict[str, float],
    current_perf: dict[str, float],
) -> list[dict]:
    """Check if inference latency p95 regressed beyond tolerance.

    Args:
        baseline_perf: Baseline performance dict with latency_p95_ms keys.
        current_perf: Current performance dict.

    Returns:
        List of regression dicts, empty if none.
    """
    regressions = []
    baseline_p95 = baseline_perf.get("latency_p95_ms", 0.0)
    current_p95 = current_perf.get("latency_p95_ms", 0.0)
    if baseline_p95 > 0 and current_p95 / baseline_p95 > LATENCY_P95_TOLERANCE:
        regressions.append({
            "metric": "latency_p95_ms",
            "baseline": baseline_p95,
            "current": current_p95,
            "ratio": round(current_p95 / baseline_p95, 3),
            "tolerance": LATENCY_P95_TOLERANCE,
        })
    return regressions


def main() -> int:
    """Run benchmarks, compare against baseline, report regressions.

    Returns:
        Exit code: 0 if passed, 1 if regressions detected.
    """
    parser = argparse.ArgumentParser(
        description="CI benchmark regression hook",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        required=True,
        help="Path to baseline benchmark report JSON",
    )
    parser.add_argument(
        "--scenario-dir",
        type=Path,
        default=Path("benchmarks/attack_scenarios"),
        help="Path to attack scenario directory",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.5,
        help="Anomaly score threshold (default: 0.5)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    if not args.baseline.exists():
        logger.error("Baseline file not found: %s", args.baseline)
        return 1

    logger.info("Loading baseline from %s", args.baseline)
    baseline = _load_baseline(args.baseline)

    logger.info("Running benchmarks on scenarios in %s", args.scenario_dir)
    bench = PipelineBenchmark(
        scenario_dir=args.scenario_dir,
        pipeline_config={},
    )
    current = bench.run(threshold=args.threshold)

    comparison = PipelineBenchmark.compare(baseline, current)

    # Print results
    print("\n" + "=" * 60)
    print("  CI Benchmark Comparison Report")
    print("=" * 60)
    print(f"\n  Baseline: {comparison.baseline_ts}")
    print(f"  Current:  {comparison.current_ts}")

    if comparison.regressions:
        print(f"\n  REGRESSIONS ({len(comparison.regressions)}):")
        for reg in comparison.regressions:
            print(f"    - {reg['metric']}: {reg}")
    else:
        print("\n  No regressions detected.")

    if comparison.improvements:
        print(f"\n  Improvements ({len(comparison.improvements)}):")
        for imp in comparison.improvements:
            print(f"    + {imp['metric']}: {imp}")

    passed = comparison.passed
    status = "PASSED" if passed else "FAILED"
    print(f"\n  Overall: {status}")
    print("=" * 60)

    # Save current report
    report_path = current.save()
    logger.info("Current report saved to %s", report_path)

    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
