"""
Missed attack audit tool for reviewing FN (false negative) decisions.

Scans recent filtered-out anomalies to identify potential attacks that were
suppressed by allowlists or threshold tuning. Produces a report for SOC review.

ATT&CK alignment: guards against suppression of T1059, T1105, T1046, T1548.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from benign_lists import NEVER_ALLOWLIST

logger = logging.getLogger(__name__)

# Filtered anomalies log (written by push_all_anomalies.py)
FILTERED_LOG: Path = Path("results/filtered_anomalies.jsonl")

# Report output location
AUDIT_REPORT: Path = Path("results/missed_attack_audit.json")

# Score threshold above which a filtered anomaly is suspicious
SUSPICIOUS_SCORE_THRESHOLD: float = 0.80

# LOLBin-related techniques that should never be silently filtered
CRITICAL_TECHNIQUES: set[str] = {
    "T1059",  # Command and Scripting Interpreter
    "T1105",  # Ingress Tool Transfer
    "T1046",  # Network Service Scanning
    "T1548",  # Abuse Elevation Control Mechanism
}


def audit_filtered_anomalies(
    filtered_log_path: Path | None = None,
    lookback_hours: int = 24,
) -> dict[str, Any]:
    """Scan filtered anomalies for potential missed attacks.

    Checks for:
    1. High-score anomalies that were filtered (score > SUSPICIOUS_SCORE_THRESHOLD)
    2. LOLBin processes that were incorrectly allowlisted
    3. Anomalies mapped to CRITICAL_TECHNIQUES that were filtered

    Args:
        filtered_log_path: Path to the filtered anomalies JSONL log.
        lookback_hours: How many hours back to scan.

    Returns:
        Audit report dict with flagged anomalies and recommendations.
    """
    log_path = filtered_log_path or FILTERED_LOG
    if not log_path.exists():
        return {"status": "no_data", "flagged": [], "total_scanned": 0}

    cutoff = datetime.now(timezone.utc).timestamp() - (lookback_hours * 3600)
    flagged: list[dict] = []
    total_scanned = 0

    with log_path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue

            total_scanned += 1

            # Parse timestamp
            ts_str = record.get("timestamp", "")
            try:
                ts = datetime.fromisoformat(ts_str).timestamp()
            except (ValueError, TypeError):
                continue

            if ts < cutoff:
                continue

            flags: list[str] = []
            score = record.get("record_score", 0.0)
            process_name = record.get("process_name", "")
            techniques = record.get("mitre_techniques", [])

            # Check 1: High score filtered
            if score >= SUSPICIOUS_SCORE_THRESHOLD:
                flags.append(f"high_score_{score:.2f}")

            # Check 2: LOLBin process
            if process_name in NEVER_ALLOWLIST:
                flags.append(f"lolbin_{process_name}")

            # Check 3: Critical technique
            for tech in techniques:
                if tech in CRITICAL_TECHNIQUES:
                    flags.append(f"critical_technique_{tech}")

            if flags:
                flagged.append({
                    "record": record,
                    "flags": flags,
                    "severity": "high" if len(flags) >= 2 else "medium",
                })

    report: dict[str, Any] = {
        "status": "complete",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "lookback_hours": lookback_hours,
        "total_scanned": total_scanned,
        "total_flagged": len(flagged),
        "flagged": flagged,
        "recommendations": _generate_recommendations(flagged),
    }

    # Write report
    AUDIT_REPORT.parent.mkdir(parents=True, exist_ok=True)
    AUDIT_REPORT.write_text(json.dumps(report, indent=2, default=str))
    logger.info(
        "Missed attack audit: scanned=%d flagged=%d",
        total_scanned,
        len(flagged),
    )

    return report


def _generate_recommendations(flagged: list[dict]) -> list[str]:
    """Generate actionable recommendations from flagged anomalies.

    Args:
        flagged: List of flagged anomaly dicts with flags.

    Returns:
        List of recommendation strings.
    """
    recommendations: list[str] = []

    lolbin_flags = [f for f in flagged if any("lolbin" in fl for fl in f["flags"])]
    if lolbin_flags:
        recommendations.append(
            f"Review {len(lolbin_flags)} filtered LOLBin anomalies. "
            "These processes should never be silently suppressed."
        )

    high_score_flags = [f for f in flagged if any("high_score" in fl for fl in f["flags"])]
    if high_score_flags:
        recommendations.append(
            f"Review {len(high_score_flags)} high-score filtered anomalies. "
            "Consider lowering allowlist dampening factors."
        )

    critical_flags = [f for f in flagged if any("critical_technique" in fl for fl in f["flags"])]
    if critical_flags:
        recommendations.append(
            f"Review {len(critical_flags)} anomalies mapped to critical ATT&CK techniques "
            "that were filtered. These may represent genuine threats."
        )

    if not recommendations:
        recommendations.append("No concerning patterns found in filtered anomalies.")

    return recommendations


if __name__ == "__main__":
    import sys
    hours = int(sys.argv[1]) if len(sys.argv) > 1 else 24
    report = audit_filtered_anomalies(lookback_hours=hours)
    print(f"Audit complete: {report['total_flagged']}/{report['total_scanned']} flagged")
    for rec in report["recommendations"]:
        print(f"  - {rec}")
