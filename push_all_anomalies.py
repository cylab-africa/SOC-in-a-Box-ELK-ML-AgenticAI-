"""
Alert filtering, dedup, enrichment, and push for the anomaly pipeline.

Agent 4 owns filtering sections:
  - filter_* functions, dedup_* functions, is_benign / should_push helpers
  - compute_effective_threshold, _build_trace

Agent 6 owns enrichment, bulk-index, and health-metric sections:
  - map_mitre_fields, enrich_anomaly, enrich_batch
  - add_context_placeholders, enrich_with_context
  - push_anomaly, bulk_index_anomalies, index_correlation_chain
  - push_to_buffer, flush_push_buffer
  - health_write, health_read, metrics_build

ATT&CK techniques referenced:
  T1059 (Command and Scripting Interpreter)
  T1046 (Network Service Scanning)
  T1548 (Abuse Elevation Control Mechanism)
  T1105 (Ingress Tool Transfer)
"""

from __future__ import annotations

import json
import logging
import uuid
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


# ===========================================================================
# AGENT 6 SECTION: Enrichment, Push, Health
# ===========================================================================

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAPPINGS_DIR = Path(__file__).parent / "mappings"
ATTACK_MAPPING_PATH = MAPPINGS_DIR / "attack_mapping.json"

KILL_CHAIN_PHASE_ORDER: dict[str, int] = {
    "reconnaissance": 1,
    "resource_development": 2,
    "initial_access": 3,
    "execution": 4,
    "persistence": 5,
    "privilege_escalation": 6,
    "defense_evasion": 7,
    "credential_access": 8,
    "discovery": 9,
    "lateral_movement": 10,
    "collection": 11,
    "command_and_control": 12,
    "exfiltration": 13,
    "impact": 14,
}

INVESTIGATION_TEMPLATES: dict[str, list[str]] = {
    "T1059": [
        "Review full command line arguments for the flagged process",
        "Check parent process — is this expected to spawn {process_name}?",
        "Look for similar commands on peer hosts in the same timeframe",
    ],
    "T1036": [
        "Compare process binary path against known-good baseline",
        "Verify digital signature of the executable if present",
        "Check process start time relative to recent deployments",
    ],
    "T1071": [
        "Inspect full network flow for the destination IP and port",
        "Check if the destination resolves to a known CDN or internal service",
        "Correlate with DNS lookups just prior to the connection",
    ],
    "T1048": [
        "Inspect data volume transferred — large transfers are high-risk",
        "Identify the protocol used and whether encryption was applied",
        "Determine the destination ownership (ASN lookup)",
    ],
    "T1078": [
        "Verify the login source IP with the user or their team",
        "Check if MFA was used for this authentication",
        "Review user login history for the past 30 days",
    ],
    "T1548": [
        "Confirm the sudo command run and whether it matches job duties",
        "Check sudoers configuration for unexpected NOPASSWD rules",
        "Review recent changes to /etc/sudoers or /etc/sudoers.d/",
    ],
    "T1082": [
        "Identify the user context running discovery commands",
        "Look for rapid sequential discovery commands — indicates reconnaissance",
        "Correlate with outbound connections immediately after discovery",
    ],
    "T1016": [
        "Check if network enumeration was followed by lateral movement",
        "Identify the initiating process parent tree",
        "Review firewall rule changes around the same time",
    ],
    "T1049": [
        "Assess whether discovered connections were then contacted externally",
        "Correlate process.name with known attacker tooling",
        "Review /proc/net/tcp for any unusual socket states",
    ],
    "T1057": [
        "Determine if process enumeration preceded privilege escalation attempts",
        "Check for enumeration of security tools (av, edr, siem processes)",
        "Look for similar ps/top patterns on adjacent hosts",
    ],
    "T1033": [
        "Verify whether the running user has anomalous group memberships",
        "Check if user enumeration preceded an account creation event",
        "Review /etc/passwd modifications in the surrounding time window",
    ],
    "T1588": [
        "Identify which compiler was invoked and what source file was compiled",
        "Check the output binary path and subsequent execution",
        "Review development environment policy — is compilation expected here?",
    ],
    "T1027": [
        "Inspect base64 or encoded strings in the command arguments",
        "Run static analysis on any dropped binaries",
        "Check for recent writes to temp directories",
    ],
    "T1571": [
        "Verify whether the non-standard port is part of any known service",
        "Correlate with firewall rule modifications",
        "Check destination IP reputation and geolocation",
    ],
    "T1136": [
        "Identify which account was created and by whom",
        "Check for immediate privilege grants to the new account",
        "Review PAM and /var/log/auth.log around the creation time",
    ],
    "T1087": [
        "Determine if account enumeration preceded privilege escalation",
        "Check LDAP or NIS queries if present",
        "Look for enumeration of service accounts specifically",
    ],
}

DEFAULT_NEXT_STEPS: list[str] = [
    "Review process and network activity on the affected host",
    "Check endpoint logs around the anomaly timestamp",
    "Correlate with other alerts for the same entity",
]


# ---------------------------------------------------------------------------
# ATT&CK mapping loader
# ---------------------------------------------------------------------------

def load_attack_mapping() -> dict[str, Any]:
    """
    Load the MITRE ATT&CK job-to-technique mapping from disk.

    Returns an empty dict if the mapping file cannot be read.
    """
    try:
        with ATTACK_MAPPING_PATH.open() as f:
            return json.load(f)
    except Exception as exc:
        logger.warning("Could not load ATT&CK mapping from %s: %s", ATTACK_MAPPING_PATH, exc)
        return {}


_ATTACK_MAPPING: dict[str, Any] = {}


def _get_attack_mapping() -> dict[str, Any]:
    """Return the cached ATT&CK mapping, loading it on first access."""
    global _ATTACK_MAPPING
    if not _ATTACK_MAPPING:
        _ATTACK_MAPPING = load_attack_mapping()
    return _ATTACK_MAPPING


# ---------------------------------------------------------------------------
# MITRE enrichment
# ---------------------------------------------------------------------------

def map_mitre_fields(anomaly: dict[str, Any]) -> dict[str, Any]:
    """
    Add MITRE ATT&CK technique fields to an anomaly document.

    Looks up the job_id in attack_mapping.json and injects:
      - mitre_tactic
      - mitre_technique_id
      - mitre_technique_name
      - mitre_techniques  (full list)
      - kill_chain_phase
      - kill_chain_phase_order

    ATT&CK: technique IDs are derived from the job mapping.
    """
    job_id = anomaly.get("job_id", "")
    mapping = _get_attack_mapping()

    job_entry = mapping.get(job_id, {})
    techniques: list[dict[str, str]] = job_entry.get("techniques", [])
    phase: str = job_entry.get("kill_chain_phase", "")

    if techniques:
        primary = techniques[0]
        anomaly["mitre_tactic"] = primary.get("tactic", "")
        anomaly["mitre_technique_id"] = primary.get("id", "")
        anomaly["mitre_technique_name"] = primary.get("name", "")
    else:
        anomaly.setdefault("mitre_tactic", "")
        anomaly.setdefault("mitre_technique_id", "")
        anomaly.setdefault("mitre_technique_name", "")

    anomaly["mitre_techniques"] = techniques
    anomaly["kill_chain_phase"] = phase
    anomaly["kill_chain_phase_order"] = KILL_CHAIN_PHASE_ORDER.get(phase, 0)
    return anomaly


def enrich_anomaly(anomaly: dict[str, Any]) -> dict[str, Any]:
    """
    Apply all enrichment passes to a single anomaly document.

    Runs MITRE mapping and assigns a correlation_id if not already set.
    """
    anomaly = map_mitre_fields(anomaly)
    anomaly.setdefault("correlation_id", str(uuid.uuid4()))
    anomaly.setdefault("pushed_at", datetime.now(tz=timezone.utc).isoformat())
    return anomaly


def enrich_batch(anomalies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Enrich a list of anomaly documents in-place.

    Returns the same list with enrichment fields added to every element.
    """
    return [enrich_anomaly(a) for a in anomalies]


# ---------------------------------------------------------------------------
# Context enrichment
# ---------------------------------------------------------------------------

def _build_next_steps(techniques: list[dict[str, str]], anomaly: dict[str, Any]) -> list[str]:
    """Build templated investigation hints from technique IDs."""
    steps: list[str] = []
    process_name = anomaly.get("process.name", anomaly.get("entity_value", "unknown"))
    for tech in techniques:
        tech_id = tech.get("id", "")
        templates = INVESTIGATION_TEMPLATES.get(tech_id, DEFAULT_NEXT_STEPS)
        for tpl in templates:
            steps.append(tpl.format(process_name=process_name))
    if not steps:
        steps = list(DEFAULT_NEXT_STEPS)
    return steps


def add_context_placeholders(anomaly: dict[str, Any]) -> dict[str, Any]:
    """
    Attach a context sub-document to an anomaly with investigation hints.

    Fields that require a live ES query (entity_anomaly_count_7d, score_percentile)
    are set to sentinel values here; use enrich_with_context for live data.
    """
    techniques = anomaly.get("mitre_techniques", [])
    anomaly["context"] = {
        "entity_anomaly_count_7d": -1,
        "entity_anomaly_trend": "unknown",
        "score_percentile": -1.0,
        "score_percentile_label": "unknown",
        "source_es_doc_ids": anomaly.get("source_doc_ids", []),
        "source_index": anomaly.get("source_index", ""),
        "recommended_next_steps": _build_next_steps(techniques, anomaly),
    }
    return anomaly


def enrich_with_context(anomaly: dict[str, Any], es: Any) -> dict[str, Any]:
    """
    Add live investigation context to an anomaly before push.

    Queries Elasticsearch for:
    - entity anomaly count over past 7 days
    - score percentile relative to the same job

    Falls back to placeholder values if ES is unavailable.

    ATT&CK: N/A (operational enrichment)
    """
    anomaly = add_context_placeholders(anomaly)

    entity = anomaly.get("entity_value", "")
    job_id = anomaly.get("job_id", "")
    score = float(anomaly.get("anomaly_score", anomaly.get("record_score", 0.0)))

    try:
        count_7d = _count_recent_anomalies(es, entity, job_id, days=7)
        anomaly["context"]["entity_anomaly_count_7d"] = count_7d
        anomaly["context"]["entity_anomaly_trend"] = _compute_trend(es, entity, job_id)

        pct = _compute_percentile(es, score, job_id)
        anomaly["context"]["score_percentile"] = pct
        anomaly["context"]["score_percentile_label"] = _percentile_label(pct)
    except Exception as exc:
        logger.warning("Context enrichment partial failure for entity=%s: %s", entity, exc)

    return anomaly


def _count_recent_anomalies(es: Any, entity: str, job_id: str, days: int) -> int:
    """Query ES for the anomaly count for an entity over the past N days."""
    query: dict[str, Any] = {
        "query": {
            "bool": {
                "filter": [
                    {"term": {"entity_value": entity}},
                    {"term": {"job_id": job_id}},
                    {"range": {"timestamp": {"gte": f"now-{days}d/d"}}},
                ]
            }
        },
        "size": 0,
    }
    result = es.count(index="ml-anomalies-custom-*", body=query)
    return int(result.get("count", 0))


def _compute_trend(es: Any, entity: str, job_id: str) -> str:
    """
    Compute whether the entity's anomaly rate is increasing, stable, or decreasing.

    Compares the last 7 days vs the preceding 7 days.
    """
    recent = _count_recent_anomalies(es, entity, job_id, days=7)
    prior_query: dict[str, Any] = {
        "query": {
            "bool": {
                "filter": [
                    {"term": {"entity_value": entity}},
                    {"term": {"job_id": job_id}},
                    {"range": {"timestamp": {"gte": "now-14d/d", "lt": "now-7d/d"}}},
                ]
            }
        },
        "size": 0,
    }
    result = es.count(index="ml-anomalies-custom-*", body=prior_query)
    prior = int(result.get("count", 0))

    if prior == 0:
        return "increasing" if recent > 0 else "stable"
    ratio = recent / prior
    if ratio > 1.2:
        return "increasing"
    if ratio < 0.8:
        return "decreasing"
    return "stable"


def _compute_percentile(es: Any, score: float, job_id: str) -> float:
    """
    Estimate the score percentile relative to all anomalies for the same job.

    Returns a value in [0.0, 100.0].
    """
    count_below_query: dict[str, Any] = {
        "query": {
            "bool": {
                "filter": [
                    {"term": {"job_id": job_id}},
                    {"range": {"anomaly_score": {"lt": score}}},
                ]
            }
        },
        "size": 0,
    }
    total_query: dict[str, Any] = {
        "query": {"term": {"job_id": job_id}},
        "size": 0,
    }
    below = int(es.count(index="ml-anomalies-custom-*", body=count_below_query).get("count", 0))
    total = int(es.count(index="ml-anomalies-custom-*", body=total_query).get("count", 1))
    if total == 0:
        return 0.0
    return round((below / total) * 100.0, 1)


def _percentile_label(percentile: float) -> str:
    """Convert a numeric percentile to a human-readable label."""
    if percentile >= 99.0:
        return "top 1%"
    if percentile >= 98.0:
        return "top 2%"
    if percentile >= 95.0:
        return "top 5%"
    if percentile >= 90.0:
        return "top 10%"
    if percentile >= 75.0:
        return "top 25%"
    return f"top {round(100.0 - percentile)}%"


# ---------------------------------------------------------------------------
# Push / bulk-index functions
# ---------------------------------------------------------------------------

ANOMALIES_INDEX = "ml-anomalies-custom"
CORRELATED_INDEX = "ml-anomalies-correlated"
PUSH_BUFFER_PATH = Path("results/push_buffer.jsonl")


def push_anomaly(es: Any, anomaly: dict[str, Any]) -> bool:
    """
    Index a single enriched anomaly document into Elasticsearch.

    Returns True on success.
    """
    doc_id = anomaly.get("anomaly_id", str(uuid.uuid4()))
    try:
        es.index(index=ANOMALIES_INDEX, id=doc_id, document=anomaly)
        logger.debug("Indexed anomaly %s", doc_id)
        return True
    except Exception as exc:
        logger.error("Failed to index anomaly %s: %s", doc_id, exc)
        return False


def bulk_index_anomalies(es: Any, anomalies: list[dict[str, Any]]) -> tuple[int, int]:
    """
    Bulk-index a list of enriched anomaly documents.

    Returns (success_count, failure_count).
    """
    if not anomalies:
        return 0, 0

    try:
        from elasticsearch.helpers import bulk as es_bulk
    except ImportError:
        # Fallback: index one by one
        success = sum(1 for a in anomalies if push_anomaly(es, a))
        return success, len(anomalies) - success

    actions = [
        {
            "_index": ANOMALIES_INDEX,
            "_id": a.get("anomaly_id", str(uuid.uuid4())),
            "_source": a,
        }
        for a in anomalies
    ]
    try:
        ok, errors = es_bulk(es, actions, raise_on_error=False)
        failure_count = len(errors) if isinstance(errors, list) else 0
        return ok, failure_count
    except Exception as exc:
        logger.error("Bulk index failed: %s", exc)
        return 0, len(anomalies)


def index_correlation_chain(es: Any, chain: dict[str, Any]) -> bool:
    """
    Index a correlated attack chain document into Elasticsearch.

    Returns True on success.
    """
    chain_id = chain.get("chain_id", str(uuid.uuid4()))
    try:
        es.index(index=CORRELATED_INDEX, id=chain_id, document=chain)
        logger.debug("Indexed correlation chain %s", chain_id)
        return True
    except Exception as exc:
        logger.error("Failed to index correlation chain %s: %s", chain_id, exc)
        return False


def push_to_buffer(anomaly: dict[str, Any]) -> None:
    """
    Append an anomaly document to the local push buffer file.

    Used when the circuit breaker is open and ES is unavailable.
    """
    PUSH_BUFFER_PATH.parent.mkdir(parents=True, exist_ok=True)
    with PUSH_BUFFER_PATH.open("a") as f:
        f.write(json.dumps(anomaly) + "\n")
    logger.debug("Buffered anomaly %s locally", anomaly.get("anomaly_id", ""))


def flush_push_buffer(es: Any) -> tuple[int, int]:
    """
    Attempt to push all locally buffered anomalies to Elasticsearch.

    Returns (success_count, failure_count). Removes the buffer on full success.
    """
    if not PUSH_BUFFER_PATH.exists():
        return 0, 0

    buffered: list[dict[str, Any]] = []
    with PUSH_BUFFER_PATH.open() as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    buffered.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

    if not buffered:
        return 0, 0

    ok, fail = bulk_index_anomalies(es, buffered)
    logger.info("Flushed buffer: %d ok, %d failed", ok, fail)
    if fail == 0:
        PUSH_BUFFER_PATH.unlink(missing_ok=True)
    return ok, fail


# ---------------------------------------------------------------------------
# Health & metrics functions
# ---------------------------------------------------------------------------

HEALTH_FILE_PATH = Path("results/health.json")


def health_write(metrics: dict[str, Any]) -> None:
    """
    Write the current service health metrics to disk as JSON.

    The health file is read by monitoring systems and the circuit breaker.
    """
    HEALTH_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    metrics["written_at"] = datetime.now(tz=timezone.utc).isoformat()
    with HEALTH_FILE_PATH.open("w") as f:
        json.dump(metrics, f, indent=2)


def health_read() -> dict[str, Any]:
    """
    Read and return the last written health metrics dict.

    Returns an empty dict if the file does not exist.
    """
    if not HEALTH_FILE_PATH.exists():
        return {}
    try:
        with HEALTH_FILE_PATH.open() as f:
            return json.load(f)
    except Exception:
        return {}


def metrics_build(
    last_run_ts: str,
    run_duration_sec: float,
    push_success: int,
    push_failure: int,
    correlation_chains: int,
    es_healthy: bool,
    model_versions: dict[str, str],
    uptime_hours: float,
) -> dict[str, Any]:
    """
    Assemble a health metrics dictionary for writing or logging.

    All parameters correspond directly to health file fields.
    """
    return {
        "last_detection_run": last_run_ts,
        "last_detection_duration_sec": run_duration_sec,
        "last_push_success_count": push_success,
        "last_push_failure_count": push_failure,
        "last_correlation_chains": correlation_chains,
        "es_connection_healthy": es_healthy,
        "model_versions": model_versions,
        "uptime_hours": round(uptime_hours, 2),
    }
