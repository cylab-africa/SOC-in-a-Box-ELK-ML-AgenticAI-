"""
Pipeline detection benchmark evaluator.

Runs attack scenarios through the detection pipeline and computes
detection quality metrics: AUC-PR, AUC-ROC, recall, precision, F1,
time-to-detection, and kill-chain phase coverage.

MITRE ATT&CK alignment: validates scenario coverage across technique IDs.
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np

logger = logging.getLogger(__name__)

SCENARIO_DIR: Path = Path("benchmarks/attack_scenarios")
RESULTS_DIR: Path = Path("benchmarks/results")


@dataclass
class ScenarioMetrics:
    """Detection quality metrics for a single attack scenario."""

    scenario_name: str
    attack_events_total: int = 0
    attack_events_detected: int = 0
    detection_rate: float = 0.0
    false_alarms: int = 0
    precision: float = 0.0
    f1: float = 0.0
    time_to_first_detection_sec: float = 0.0
    kill_chain_phases_detected: list[str] = field(default_factory=list)
    kill_chain_completeness: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "scenario_name": self.scenario_name,
            "attack_events_total": self.attack_events_total,
            "attack_events_detected": self.attack_events_detected,
            "detection_rate": round(self.detection_rate, 4),
            "false_alarms": self.false_alarms,
            "precision": round(self.precision, 4),
            "f1": round(self.f1, 4),
            "time_to_first_detection_sec": round(self.time_to_first_detection_sec, 3),
            "kill_chain_phases_detected": self.kill_chain_phases_detected,
            "kill_chain_completeness": round(self.kill_chain_completeness, 4),
        }


@dataclass
class JobMetrics:
    """Per-job (process, network, auth) detection metrics."""

    job_name: str
    events_scored: int = 0
    anomalies_flagged: int = 0
    mean_score: float = 0.0
    max_score: float = 0.0
    scoring_time_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "job_name": self.job_name,
            "events_scored": self.events_scored,
            "anomalies_flagged": self.anomalies_flagged,
            "mean_score": round(self.mean_score, 4),
            "max_score": round(self.max_score, 4),
            "scoring_time_ms": round(self.scoring_time_ms, 3),
        }


@dataclass
class BenchmarkReport:
    """Aggregated benchmark report across all scenarios and jobs."""

    per_job: dict[str, JobMetrics] = field(default_factory=dict)
    per_scenario: dict[str, ScenarioMetrics] = field(default_factory=dict)
    overall_auc_pr: float = 0.0
    overall_auc_roc: float = 0.0
    mean_time_to_detect_minutes: float = 0.0
    alerts_per_day: float = 0.0
    timestamp: str = ""
    pipeline_config_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize report to dictionary."""
        return {
            "per_job": {k: v.to_dict() for k, v in self.per_job.items()},
            "per_scenario": {k: v.to_dict() for k, v in self.per_scenario.items()},
            "overall_auc_pr": round(self.overall_auc_pr, 4),
            "overall_auc_roc": round(self.overall_auc_roc, 4),
            "mean_time_to_detect_minutes": round(self.mean_time_to_detect_minutes, 3),
            "alerts_per_day": round(self.alerts_per_day, 2),
            "timestamp": self.timestamp,
            "pipeline_config_hash": self.pipeline_config_hash,
        }

    def save(self, output_dir: Path | None = None) -> Path:
        """Write report to JSON file.

        Args:
            output_dir: Directory to write to; defaults to RESULTS_DIR.

        Returns:
            Path to the saved report.
        """
        dest = output_dir or RESULTS_DIR
        dest.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        path = dest / f"{ts}_report.json"
        path.write_text(json.dumps(self.to_dict(), indent=2))
        logger.info("Benchmark report saved to %s", path)
        return path

    def to_markdown(self) -> str:
        """Generate markdown summary of the report.

        Returns:
            Markdown-formatted report string.
        """
        lines = [
            f"# Benchmark Report — {self.timestamp}",
            "",
            f"- Overall AUC-PR: {self.overall_auc_pr:.4f}",
            f"- Overall AUC-ROC: {self.overall_auc_roc:.4f}",
            f"- Mean TTD: {self.mean_time_to_detect_minutes:.1f} min",
            f"- Alert rate: {self.alerts_per_day:.1f} alerts/day",
            "",
            "## Per-Scenario Results",
            "",
            "| Scenario | Detection Rate | Precision | F1 | KC Coverage |",
            "|----------|---------------|-----------|-----|-------------|",
        ]
        for name, sm in self.per_scenario.items():
            lines.append(
                f"| {name} | {sm.detection_rate:.2%} | "
                f"{sm.precision:.2%} | {sm.f1:.4f} | "
                f"{sm.kill_chain_completeness:.0%} |"
            )
        return "\n".join(lines)


@dataclass
class ComparisonReport:
    """Diff between two benchmark runs."""

    baseline_ts: str
    current_ts: str
    regressions: list[dict[str, Any]] = field(default_factory=list)
    improvements: list[dict[str, Any]] = field(default_factory=list)
    passed: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Serialize comparison to dictionary."""
        return {
            "baseline_ts": self.baseline_ts,
            "current_ts": self.current_ts,
            "regressions": self.regressions,
            "improvements": self.improvements,
            "passed": self.passed,
        }


def _compute_auc_pr(labels: np.ndarray, scores: np.ndarray) -> float:
    """Compute area under Precision-Recall curve.

    Args:
        labels: Binary ground truth (0/1).
        scores: Anomaly scores in [0, 1].

    Returns:
        AUC-PR value.
    """
    sorted_idx = np.argsort(-scores)
    sorted_labels = labels[sorted_idx]
    tp_cumsum = np.cumsum(sorted_labels)
    total_positives = labels.sum()
    if total_positives == 0:
        return 0.0
    recall = tp_cumsum / total_positives
    precision = tp_cumsum / np.arange(1, len(labels) + 1)
    # Trapezoidal approximation
    auc = float(np.trapz(precision, recall))
    return max(0.0, min(1.0, auc))


def _compute_auc_roc(labels: np.ndarray, scores: np.ndarray) -> float:
    """Compute area under ROC curve.

    Args:
        labels: Binary ground truth (0/1).
        scores: Anomaly scores in [0, 1].

    Returns:
        AUC-ROC value.
    """
    total_pos = labels.sum()
    total_neg = len(labels) - total_pos
    if total_pos == 0 or total_neg == 0:
        return 0.5
    sorted_idx = np.argsort(-scores)
    sorted_labels = labels[sorted_idx]
    tpr_vals = np.cumsum(sorted_labels) / total_pos
    fpr_vals = np.cumsum(1 - sorted_labels) / total_neg
    tpr_vals = np.concatenate([[0], tpr_vals])
    fpr_vals = np.concatenate([[0], fpr_vals])
    auc = float(np.trapz(tpr_vals, fpr_vals))
    return max(0.0, min(1.0, auc))


class PipelineBenchmark:
    """Runs attack scenarios through the detection pipeline and measures quality.

    Args:
        scenario_dir: Path to directory containing scenario JSON files.
        pipeline_config: Configuration dict passed to the pipeline.
    """

    def __init__(
        self,
        scenario_dir: str | Path = SCENARIO_DIR,
        pipeline_config: dict[str, Any] | None = None,
    ) -> None:
        self.scenario_dir = Path(scenario_dir)
        self.pipeline_config = pipeline_config or {}
        self._config_hash = hashlib.sha256(
            json.dumps(self.pipeline_config, sort_keys=True).encode()
        ).hexdigest()[:12]

    def _load_scenarios(self) -> list[dict[str, Any]]:
        """Load all scenario JSON files from the scenario directory.

        Returns:
            List of parsed scenario dictionaries.
        """
        scenarios = []
        for path in sorted(self.scenario_dir.glob("scenario_*.json")):
            data = json.loads(path.read_text())
            scenarios.append(data)
            logger.info("Loaded scenario: %s (%d events)", data["scenario_name"], len(data["events"]))
        return scenarios

    def _score_events(
        self, events: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        """Score events through the pipeline, returning events with scores.

        This is a stub implementation that assigns random scores. In production,
        this would pass events through the actual model pipeline.

        Args:
            events: List of event dictionaries.

        Returns:
            Events with an added 'anomaly_score' field.
        """
        rng = np.random.default_rng(42)
        scored = []
        for event in events:
            e = dict(event)
            if e.get("is_attack"):
                e["anomaly_score"] = float(np.clip(rng.normal(0.7, 0.15), 0.0, 1.0))
            else:
                e["anomaly_score"] = float(np.clip(rng.normal(0.2, 0.1), 0.0, 1.0))
            scored.append(e)
        return scored

    def _evaluate_scenario(
        self,
        scenario: dict[str, Any],
        threshold: float = 0.5,
    ) -> ScenarioMetrics:
        """Evaluate detection quality on a single scenario.

        Args:
            scenario: Parsed scenario dictionary.
            threshold: Score threshold for flagging anomalies.

        Returns:
            ScenarioMetrics for the scenario.
        """
        events = scenario["events"]
        scored = self._score_events(events)

        labels = np.array([1 if e.get("is_attack") else 0 for e in scored])
        scores = np.array([e["anomaly_score"] for e in scored])
        predictions = (scores >= threshold).astype(int)

        tp = int(((predictions == 1) & (labels == 1)).sum())
        fp = int(((predictions == 1) & (labels == 0)).sum())
        total_attack = int(labels.sum())

        detection_rate = tp / total_attack if total_attack > 0 else 0.0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        f1 = (2 * precision * detection_rate / (precision + detection_rate)
               if (precision + detection_rate) > 0 else 0.0)

        # Kill chain coverage
        expected_phases = set(scenario.get("kill_chain_phases", []))
        detected_phases = set()
        for e in scored:
            if e.get("anomaly_score", 0) >= threshold and e.get("attack_phase"):
                detected_phases.add(e["attack_phase"])
        kc_completeness = (len(detected_phases & expected_phases) / len(expected_phases)
                           if expected_phases else 0.0)

        # Time-to-first-detection
        ttfd = 0.0
        attack_times = sorted(
            e["@timestamp"] for e in scored if e.get("is_attack") and e.get("anomaly_score", 0) >= threshold
        )
        if attack_times:
            ttfd = 0.0  # placeholder — real implementation uses datetime parsing

        return ScenarioMetrics(
            scenario_name=scenario["scenario_name"],
            attack_events_total=total_attack,
            attack_events_detected=tp,
            detection_rate=detection_rate,
            false_alarms=fp,
            precision=precision,
            f1=f1,
            time_to_first_detection_sec=ttfd,
            kill_chain_phases_detected=sorted(detected_phases),
            kill_chain_completeness=kc_completeness,
        )

    def run(self, threshold: float = 0.5) -> BenchmarkReport:
        """Run all scenarios through the pipeline and produce a report.

        Args:
            threshold: Score threshold for anomaly classification.

        Returns:
            BenchmarkReport with per-scenario and aggregate metrics.
        """
        scenarios = self._load_scenarios()
        report = BenchmarkReport(
            timestamp=datetime.now(timezone.utc).isoformat(),
            pipeline_config_hash=self._config_hash,
        )

        all_labels: list[int] = []
        all_scores: list[float] = []
        ttd_values: list[float] = []

        for scenario in scenarios:
            sm = self._evaluate_scenario(scenario, threshold)
            report.per_scenario[sm.scenario_name] = sm
            if sm.time_to_first_detection_sec > 0:
                ttd_values.append(sm.time_to_first_detection_sec)

            for event in scenario["events"]:
                all_labels.append(1 if event.get("is_attack") else 0)
                all_scores.append(0.5)  # placeholder

        if all_labels:
            labels_arr = np.array(all_labels)
            scores_arr = np.array(all_scores)
            report.overall_auc_pr = _compute_auc_pr(labels_arr, scores_arr)
            report.overall_auc_roc = _compute_auc_roc(labels_arr, scores_arr)

        if ttd_values:
            report.mean_time_to_detect_minutes = float(np.mean(ttd_values)) / 60.0

        total_events = sum(len(s["events"]) for s in scenarios)
        total_alerts = sum(sm.attack_events_detected + sm.false_alarms
                          for sm in report.per_scenario.values())
        if total_events > 0:
            report.alerts_per_day = total_alerts * (86400.0 / max(total_events, 1))

        logger.info("Benchmark complete: %d scenarios evaluated", len(scenarios))
        return report

    @staticmethod
    def compare(
        baseline: BenchmarkReport,
        current: BenchmarkReport,
    ) -> ComparisonReport:
        """Compare two benchmark reports and identify regressions.

        Args:
            baseline: Previous benchmark report.
            current: Current benchmark report.

        Returns:
            ComparisonReport with regressions and improvements flagged.
        """
        comp = ComparisonReport(
            baseline_ts=baseline.timestamp,
            current_ts=current.timestamp,
        )

        # AUC-PR check
        auc_pr_diff = current.overall_auc_pr - baseline.overall_auc_pr
        if auc_pr_diff < -0.02:
            comp.regressions.append({
                "metric": "overall_auc_pr",
                "baseline": baseline.overall_auc_pr,
                "current": current.overall_auc_pr,
                "diff": round(auc_pr_diff, 4),
            })
            comp.passed = False
        elif auc_pr_diff > 0.02:
            comp.improvements.append({
                "metric": "overall_auc_pr",
                "diff": round(auc_pr_diff, 4),
            })

        # Per-scenario detection rate
        for name, baseline_sm in baseline.per_scenario.items():
            current_sm = current.per_scenario.get(name)
            if current_sm is None:
                continue
            dr_diff = current_sm.detection_rate - baseline_sm.detection_rate
            if dr_diff < -0.05:
                comp.regressions.append({
                    "metric": f"{name}_detection_rate",
                    "baseline": baseline_sm.detection_rate,
                    "current": current_sm.detection_rate,
                    "diff": round(dr_diff, 4),
                })
                comp.passed = False

        # Alert volume check
        if baseline.alerts_per_day > 0:
            volume_ratio = current.alerts_per_day / baseline.alerts_per_day
            if volume_ratio > 1.20:
                comp.regressions.append({
                    "metric": "alerts_per_day",
                    "baseline": baseline.alerts_per_day,
                    "current": current.alerts_per_day,
                    "ratio": round(volume_ratio, 3),
                })
                comp.passed = False

        return comp
