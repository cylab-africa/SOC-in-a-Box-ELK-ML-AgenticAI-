"""
Alert filtering, dedup, and traceability for the anomaly push pipeline.

Agent 4 owns this file's filtering sections:
  - filter_* functions
  - dedup_* functions
  - is_benign / should_push helpers

Agent 6 owns enrichment, bulk-index, and health-metric sections —
do NOT add enrichment logic here.

ATT&CK techniques referenced:
  T1059 (Command and Scripting Interpreter)
  T1046 (Network Service Scanning)
  T1548 (Abuse Elevation Control Mechanism)
  T1105 (Ingress Tool Transfer)
"""

import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from benign_lists import AllowlistManager
from config import AdaptiveThreshold

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEDUP_WINDOW_HOURS: int = 4
SCORE_ESCALATION_DELTA: float = 0.20  # 20% higher score forces re-push
THRESHOLD_AUDIT_LOG: Path = Path("results/threshold_audit.json")

# ---------------------------------------------------------------------------
# Dedup state (in-process; callers may inject a persistent store)
# ---------------------------------------------------------------------------

# Maps (entity, job_id) -> {"score": float, "window_start": datetime, "count": int}
_DEDUP_STATE: dict[tuple[str, str], dict[str, Any]] = {}


# ---------------------------------------------------------------------------
# Adaptive threshold helpers
# ---------------------------------------------------------------------------

def compute_effective_threshold(
    job_id: str,
    entity: str,
    raw_score: float,
    threshold_cfg: AdaptiveThreshold,
    evaluation_time: Optional[datetime] = None,
) -> tuple[float, dict[str, Any]]:
    """Compute the effective push threshold for a single alert.

    Returns (effective_threshold, components_dict) where components_dict
    carries the breakdown written to threshold_audit.json.

    ATT&CK: threshold tuning reduces FN for T1059, T1046, T1548.
    """
    now = evaluation_time or datetime.now(timezone.utc)
    hour = now.hour

    base = threshold_cfg.base_score
    time_adj = 1.0
    host_adj = 1.0

    is_off_hours = hour < threshold_cfg.business_hours_start or hour >= threshold_cfg.business_hours_end
    if is_off_hours:
        time_adj = threshold_cfg.off_hours_multiplier

    is_high_value = entity in threshold_cfg.high_value_hosts
    if is_high_value:
        host_adj = threshold_cfg.high_value_host_multiplier

    effective = base * time_adj * host_adj

    # Per-job override takes precedence over computed value
    if job_id in threshold_cfg.per_job_overrides:
        effective = threshold_cfg.per_job_overrides[job_id] * time_adj * host_adj

    components: dict[str, Any] = {
        "base": base,
        "time_adj": time_adj,
        "host_adj": host_adj,
        "off_hours": is_off_hours,
        "high_value_host": is_high_value,
        "per_job_override": threshold_cfg.per_job_overrides.get(job_id),
    }

    reason_parts = [f"base={base}"]
    if time_adj != 1.0:
        reason_parts.append(f"off_hours=*{time_adj}")
    if host_adj != 1.0:
        reason_parts.append(f"high_value_host=*{host_adj}")
    if components["per_job_override"] is not None:
        reason_parts.append(f"per_job_override={components['per_job_override']}")
    reason_parts.append(f"-> {effective:.4f}")

    decision = "push" if raw_score >= effective else "drop"

    audit_record: dict[str, Any] = {
        "timestamp": now.isoformat(),
        "job_id": job_id,
        "entity": entity,
        "raw_score": raw_score,
        "effective_threshold": round(effective, 4),
        "reason": ", ".join(reason_parts),
        "decision": decision,
    }
    _append_threshold_audit(audit_record)

    return effective, components


def _append_threshold_audit(record: dict[str, Any]) -> None:
    """Append one threshold-decision record to the audit log (JSON lines)."""
    THRESHOLD_AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    try:
        with THRESHOLD_AUDIT_LOG.open("a") as fh:
            fh.write(json.dumps(record) + "\n")
    except OSError as exc:
        logger.warning("Failed to write threshold audit: %s", exc)


# ---------------------------------------------------------------------------
# Dedup logic
# ---------------------------------------------------------------------------

def dedup_key(entity: str, job_id: str) -> tuple[str, str]:
    """Return the canonical dedup key for an (entity, job_id) pair."""
    return (entity, job_id)


def is_correlated_chain(alert: dict[str, Any]) -> bool:
    """Return True if this alert is part of a post_correlation chain.

    Correlated-chain members always bypass dedup so the full kill-chain
    is visible to analysts.
    """
    return bool(alert.get("correlation_chain_id"))


def dedup_filter(
    alert: dict[str, Any],
    dedup_state: Optional[dict[tuple[str, str], dict[str, Any]]] = None,
) -> tuple[bool, str, dict[str, Any]]:
    """Apply 4-hour window dedup with score-escalation override.

    Returns (should_push, dedup_status, state_update).

    Dedup statuses:
      "first_occurrence"   — no prior entry in window, push normally
      "escalation"         — score >=20% higher than last pushed, force-push
      "clustered"          — within window and not escalated, suppress
      "chain_bypass"       — part of a correlated chain, always push
    """
    state = dedup_state if dedup_state is not None else _DEDUP_STATE

    entity = alert.get("entity", "")
    job_id = alert.get("job_id", "")
    score = float(alert.get("score", 0.0))
    now = datetime.now(timezone.utc)
    key = dedup_key(entity, job_id)

    # Correlated chains bypass dedup entirely
    if is_correlated_chain(alert):
        return True, "chain_bypass", {}

    prior = state.get(key)
    window_start = prior["window_start"] if prior else None
    in_window = (
        prior is not None
        and isinstance(window_start, datetime)
        and (now - window_start) < timedelta(hours=DEDUP_WINDOW_HOURS)
    )

    if not in_window:
        # New window — first occurrence
        state[key] = {
            "score": score,
            "window_start": now,
            "count": 1,
            "similar_count": 0,
        }
        return True, "first_occurrence", {"score": score, "window_start": now, "count": 1, "similar_count": 0}

    # Within window — check for escalation
    prior_score = prior["score"]
    if score >= prior_score * (1.0 + SCORE_ESCALATION_DELTA):
        logger.info(
            "Score escalation for %s/%s: %.3f -> %.3f (delta %.1f%%)",
            entity, job_id, prior_score, score,
            (score / prior_score - 1.0) * 100,
        )
        state[key] = {
            "score": score,
            "window_start": prior["window_start"],
            "count": prior["count"] + 1,
            "similar_count": prior.get("similar_count", 0),
        }
        return True, "escalation", state[key]

    # Cluster — suppress but track count
    prior["count"] += 1
    prior["similar_count"] = prior.get("similar_count", 0) + 1
    return False, "clustered", prior


# ---------------------------------------------------------------------------
# Core filter pipeline
# ---------------------------------------------------------------------------

def filter_alert(
    alert: dict[str, Any],
    allowlist_mgr: AllowlistManager,
    threshold_cfg: AdaptiveThreshold,
    dedup_state: Optional[dict[tuple[str, str], dict[str, Any]]] = None,
    evaluation_time: Optional[datetime] = None,
) -> tuple[bool, dict[str, Any]]:
    """Run the full filtering pipeline for a single alert.

    Steps:
      1. Allowlist dampening (benign_lists)
      2. Adaptive threshold gate
      3. Dedup / escalation check

    Returns (push_flag, filter_trace).  The filter_trace is attached to the
    alert before forwarding to Agent 6's enrichment stage.
    """
    process_name: str = alert.get("process_name", alert.get("process.name", ""))
    job_id: str = alert.get("job_id", "")
    entity: str = alert.get("entity", alert.get("host.name", ""))
    raw_score: float = float(alert.get("score", 0.0))

    # --- Step 1: Allowlist dampening ---
    dampened_score, al_trace = allowlist_mgr.apply(process_name, raw_score)

    # --- Step 2: Adaptive threshold ---
    effective_threshold, threshold_components = compute_effective_threshold(
        job_id=job_id,
        entity=entity,
        raw_score=dampened_score,
        threshold_cfg=threshold_cfg,
        evaluation_time=evaluation_time,
    )

    above_threshold = dampened_score >= effective_threshold

    if not above_threshold:
        trace = _build_trace(
            al_trace=al_trace,
            raw_score=raw_score,
            dampened_score=dampened_score,
            threshold_used=effective_threshold,
            threshold_components=threshold_components,
            dedup_status="n/a",
            final_decision="dropped_below_threshold",
        )
        return False, trace

    # --- Step 3: Dedup ---
    alert_with_score = dict(alert)
    alert_with_score["score"] = dampened_score
    should_push, dedup_status, _ = dedup_filter(alert_with_score, dedup_state)

    # Attach similar_count for clustered representative
    if dedup_status == "first_occurrence" and dedup_state is not None:
        key = dedup_key(entity, job_id)
        similar = dedup_state.get(key, {}).get("similar_count", 0)
        if similar > 0:
            alert["similar_count"] = similar

    decision = "push" if should_push else "dropped_dedup"
    trace = _build_trace(
        al_trace=al_trace,
        raw_score=raw_score,
        dampened_score=dampened_score,
        threshold_used=effective_threshold,
        threshold_components=threshold_components,
        dedup_status=dedup_status,
        final_decision=decision,
    )
    return should_push, trace


def _build_trace(
    al_trace: dict[str, Any],
    raw_score: float,
    dampened_score: float,
    threshold_used: float,
    threshold_components: dict[str, Any],
    dedup_status: str,
    final_decision: str,
) -> dict[str, Any]:
    """Assemble the filter_trace dict attached to every processed alert."""
    return {
        "filter_trace": {
            "allowlist_checked": al_trace.get("allowlist_checked", True),
            "allowlist_match": al_trace.get("allowlist_match"),
            "dampening_applied": al_trace.get("dampening_applied", 1.0),
            "lolbin_protected": al_trace.get("lolbin_protected", False),
            "original_score": raw_score,
            "dampened_score": dampened_score,
            "threshold_used": threshold_used,
            "threshold_components": threshold_components,
            "dedup_status": dedup_status,
            "final_decision": final_decision,
        }
    }


def should_push(
    alert: dict[str, Any],
    allowlist_mgr: AllowlistManager,
    threshold_cfg: AdaptiveThreshold,
    dedup_state: Optional[dict[tuple[str, str], dict[str, Any]]] = None,
    evaluation_time: Optional[datetime] = None,
) -> tuple[bool, dict[str, Any]]:
    """Public entry-point: decide whether an alert should be pushed.

    Returns (push_flag, enriched_alert) where enriched_alert has the
    filter_trace field attached.  Callers should forward enriched_alert
    to Agent 6's bulk-push pipeline.
    """
    push_flag, trace = filter_alert(
        alert=alert,
        allowlist_mgr=allowlist_mgr,
        threshold_cfg=threshold_cfg,
        dedup_state=dedup_state,
        evaluation_time=evaluation_time,
    )
    enriched = dict(alert)
    enriched.update(trace)
    return push_flag, enriched


def is_benign(
    alert: dict[str, Any],
    allowlist_mgr: AllowlistManager,
    threshold_cfg: AdaptiveThreshold,
    evaluation_time: Optional[datetime] = None,
) -> bool:
    """Convenience check: return True only if an alert is definitively benign.

    An alert is benign when dampened score falls below threshold AND the
    process is not LOLBin-protected.  Callers that need the full trace
    should use should_push() instead.
    """
    process_name: str = alert.get("process_name", alert.get("process.name", ""))
    raw_score: float = float(alert.get("score", 0.0))
    job_id: str = alert.get("job_id", "")
    entity: str = alert.get("entity", alert.get("host.name", ""))

    dampened, al_trace = allowlist_mgr.apply(process_name, raw_score)
    if al_trace.get("lolbin_protected"):
        return False

    effective, _ = compute_effective_threshold(
        job_id=job_id,
        entity=entity,
        raw_score=dampened,
        threshold_cfg=threshold_cfg,
        evaluation_time=evaluation_time,
    )
    return dampened < effective
