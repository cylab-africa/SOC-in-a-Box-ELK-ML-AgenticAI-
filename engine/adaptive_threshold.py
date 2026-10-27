"""
Adaptive threshold computation for anomaly score filtering.

Replaces the static MIN_PUSH_ML_SCORE with per-job, time-aware,
host-aware thresholds that reduce FN while keeping FP under control.

ATT&CK alignment: adaptive thresholds improve detection for T1059,
T1046, T1548 during off-hours and on high-value hosts.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

# Default threshold when no config is available
DEFAULT_BASE_SCORE: float = 0.65

# Per-job overrides — network jobs more sensitive, sudo jobs higher bar
DEFAULT_JOB_OVERRIDES: dict[str, float] = {
    "v3_linux_anomalous_network_activity": 0.55,
    "v3_linux_rare_sudo_activity": 0.70,
    "v3_linux_anomalous_process_all_hosts": 0.65,
    "v3_linux_rare_discovery_activity": 0.60,
}

# Business hours (local time)
BUSINESS_HOURS_START: int = 6
BUSINESS_HOURS_END: int = 18

# Multipliers for off-hours and high-value hosts (< 1.0 = more sensitive)
OFF_HOURS_MULTIPLIER: float = 0.85
HIGH_VALUE_HOST_MULTIPLIER: float = 0.80


def compute_effective_threshold(
    job_name: str,
    hostname: str | None = None,
    timestamp: datetime | None = None,
    high_value_hosts: list[str] | None = None,
    base_score: float | None = None,
) -> tuple[float, dict]:
    """Compute the effective push threshold for an anomaly alert.

    Returns the threshold and a trace dict documenting the computation.

    Args:
        job_name: ML job identifier.
        hostname: Host where the anomaly was detected.
        timestamp: When the anomaly was detected (UTC).
        high_value_hosts: List of hostnames considered high-value.
        base_score: Override for the base score. Default 0.65.

    Returns:
        Tuple of (effective_threshold, trace_dict).
    """
    trace: dict = {
        "base_score": base_score or DEFAULT_BASE_SCORE,
        "job_override": None,
        "off_hours_applied": False,
        "high_value_applied": False,
        "effective_threshold": 0.0,
    }

    # Start with base or per-job override
    threshold = DEFAULT_JOB_OVERRIDES.get(job_name, base_score or DEFAULT_BASE_SCORE)
    if job_name in DEFAULT_JOB_OVERRIDES:
        trace["job_override"] = threshold

    # Off-hours multiplier
    if timestamp is not None:
        hour = timestamp.hour
        if hour < BUSINESS_HOURS_START or hour >= BUSINESS_HOURS_END:
            threshold *= OFF_HOURS_MULTIPLIER
            trace["off_hours_applied"] = True

    # High-value host multiplier
    if hostname and high_value_hosts and hostname in high_value_hosts:
        threshold *= HIGH_VALUE_HOST_MULTIPLIER
        trace["high_value_applied"] = True

    trace["effective_threshold"] = round(threshold, 4)
    return threshold, trace


def build_filter_trace(
    anomaly_doc: dict,
    is_fp: bool,
    fp_reason: str | None,
    threshold_trace: dict | None = None,
    allowlist_trace: dict | None = None,
) -> dict:
    """Build a comprehensive filter_trace audit field for an anomaly document.

    This trace is attached to every alert (pushed and filtered) to enable
    post-hoc audit of filtering decisions.

    Args:
        anomaly_doc: The anomaly document being processed.
        is_fp: Whether the anomaly was classified as a false positive.
        fp_reason: Human-readable reason for FP classification (or None).
        threshold_trace: Trace from compute_effective_threshold.
        allowlist_trace: Trace from AllowlistManager.apply.

    Returns:
        Dict suitable for inclusion as 'filter_trace' in the anomaly doc.
    """
    trace: dict = {
        "filtered": is_fp,
        "reason": fp_reason,
        "threshold": threshold_trace,
        "allowlist": allowlist_trace,
        "job_name": anomaly_doc.get("job_id", "unknown"),
        "record_score": anomaly_doc.get("record_score", 0.0),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    return trace
