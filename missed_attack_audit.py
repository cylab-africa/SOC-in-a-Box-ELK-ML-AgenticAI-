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


def format_markdown_report(report: dict[str, Any]) -> str:
    """Format the audit report as a Markdown document.

    Args:
        report: Audit report dict from audit_filtered_anomalies().

    Returns:
        Markdown-formatted string.
    """
    lines: list[str] = [
        "# Missed Attack Audit Report",
        "",
        f"**Generated**: {report.get('generated_at', 'N/A')}",
        f"**Lookback**: {report.get('lookback_hours', 'N/A')} hours",
        f"**Total scanned**: {report.get('total_scanned', 0)}",
        f"**Total flagged**: {report.get('total_flagged', 0)}",
        "",
    ]

    if report.get("status") == "no_data":
        lines.append("No filtered anomaly data found.")
        return "\n".join(lines)

    # Recommendations
    lines.append("## Recommendations")
    lines.append("")
    for rec in report.get("recommendations", []):
        lines.append(f"- {rec}")
    lines.append("")

    # Flagged items
    flagged = report.get("flagged", [])
    if flagged:
        lines.append("## Flagged Anomalies")
        lines.append("")
        lines.append("| # | Severity | Flags | Process | Score | IOC Match |")
        lines.append("|---|----------|-------|---------|-------|-----------|")
        for i, item in enumerate(flagged, 1):
            record = item.get("record", {})
            severity = item.get("severity", "medium")
            flags = ", ".join(item.get("flags", []))
            proc = record.get("process_name", "N/A")
            score = record.get("record_score", 0.0)
            ioc = ", ".join(item.get("ioc_matches", [])) or "N/A"
            lines.append(f"| {i} | {severity} | {flags} | {proc} | {score:.2f} | {ioc} |")
        lines.append("")

    return "\n".join(lines)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Scan filtered anomalies for potential missed attacks"
    )
    parser.add_argument(
        "--timerange",
        type=str,
        default="24h",
        help="Lookback window, e.g. '24h', '48h', '7d' (default: 24h)",
    )
    parser.add_argument(
        "--iocs",
        type=str,
        default=None,
        help="Path to JSON file with IOCs to cross-reference",
    )
    parser.add_argument(
        "--markdown",
        action="store_true",
        help="Output report in Markdown format",
    )
    args = parser.parse_args()

    # Parse timerange to hours
    tr = args.timerange.strip().lower()
    if tr.endswith("d"):
        hours = int(tr[:-1]) * 24
    elif tr.endswith("h"):
        hours = int(tr[:-1])
    else:
        hours = int(tr)

    # Load IOCs if provided
    ioc_list: list[str] = []
    if args.iocs:
        iocs_path = Path(args.iocs)
        if iocs_path.exists():
            ioc_data = json.loads(iocs_path.read_text())
            if isinstance(ioc_data, list):
                ioc_list = [str(i) for i in ioc_data]
            elif isinstance(ioc_data, dict):
                for v in ioc_data.values():
                    if isinstance(v, list):
                        ioc_list.extend(str(i) for i in v)

    report = audit_filtered_anomalies(lookback_hours=hours)

    # Cross-reference IOCs if provided
    if ioc_list and report.get("flagged"):
        ioc_matches: list[dict] = []
        for item in report["flagged"]:
            record = item.get("record", {})
            record_str = json.dumps(record).lower()
            matched_iocs = [ioc for ioc in ioc_list if ioc.lower() in record_str]
            if matched_iocs:
                item["ioc_matches"] = matched_iocs
                item["severity"] = "critical"
                ioc_matches.append(item)
        report["ioc_matches"] = len(ioc_matches)

    if args.markdown:
        print(format_markdown_report(report))
    else:
        print(f"Audit complete: {report['total_flagged']}/{report['total_scanned']} flagged")
        for rec in report["recommendations"]:
            print(f"  - {rec}")
