# Agent 6: Push & Correlation Hardener

## Identity
You make the output actionable for SOC analysts. Every alert should tell a story.
Correlations should surface attack chains, not isolated blips.

## Files You Own (WRITE access)
- `push_all_anomalies.py` — ONLY enrichment, push, and health sections
- `post_correlation.py` — full ownership
- `realtime_service.py` — full ownership
- `mappings/` — new directory for ES index mappings (create)
- `requirements-ops.txt` (create if needed)

## Files You Read (DO NOT MODIFY)
- `model_manager.py`, `detection_methods.py` — understand scoring
- `datamanager.py` — understand ES queries
- `config.py` — read config values
- `benign_lists.py` — understand what Agent 4 filters

## CRITICAL: Shared File Boundary
`push_all_anomalies.py` is shared with Agent 4. Your territory:
- Enrichment functions: `enrich_*`, `add_context_*`, `map_mitre_*`
- Bulk index / push functions: `push_*`, `bulk_index_*`, `index_*`
- Health and metrics functions: `health_*`, `metrics_*`

Agent 4's territory:
- Filter functions: `filter_*`, `dedup_*`, `is_benign*`, `should_push*`

DO NOT touch Agent 4's filtering logic.

## What You Must Build

### 1. MITRE ATT&CK Enrichment

Create a mapping table (can live in `mappings/attack_mapping.json`):
```json
{
  "v3_linux_anomalous_process_all_hosts": {
    "techniques": [
      {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
      {"id": "T1036", "name": "Masquerading", "tactic": "Defense Evasion"}
    ],
    "kill_chain_phase": "execution"
  },
  "v3_linux_anomalous_network_activity": {
    "techniques": [
      {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
      {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"}
    ],
    "kill_chain_phase": "command_and_control"
  }
}
```

Every pushed anomaly document gets these fields:
```json
{
  "mitre_tactic": "Execution",
  "mitre_technique_id": "T1059",
  "mitre_technique_name": "Command and Scripting Interpreter",
  "kill_chain_phase": "execution",
  "kill_chain_phase_order": 4
}
```

Kill chain phase ordering (for correlation scoring):
1. reconnaissance, 2. resource_development, 3. initial_access,
4. execution, 5. persistence, 6. privilege_escalation,
7. defense_evasion, 8. credential_access, 9. discovery,
10. lateral_movement, 11. collection, 12. command_and_control,
13. exfiltration, 14. impact

### 2. Three-Way Correlation (post_correlation.py)

Upgrade from process ↔ network to user ↔ process ↔ network:

```python
class KillChainCorrelator:
    def correlate(self, anomalies: list[dict],
                  time_window_minutes: int = 60) -> list[CorrelatedChain]:
        """
        Group anomalies into attack chains by:
        1. Same host AND overlapping time window
        2. Kill chain phase ordering (earlier phase → later phase)
        3. Entity linkage (same user OR same process tree OR same dest IP)
        
        Score chain higher when:
        - More kill chain phases covered
        - Phases are in logical order
        - Multiple entity types linked (user + process + network)
        """
```

Chain output:
```json
{
  "chain_id": "chain-abc123",
  "host": "webserver-01",
  "chain_score": 0.92,
  "chain_completeness": 0.6,
  "phases_observed": ["execution", "discovery", "lateral_movement"],
  "phases_missing": ["initial_access", "persistence", "exfiltration"],
  "member_anomalies": ["anom-1", "anom-2", "anom-3"],
  "linked_entities": {
    "users": ["admin", "www-data"],
    "processes": ["bash", "python3", "ssh"],
    "dest_ips": ["10.0.1.5", "10.0.1.12"]
  },
  "time_span_minutes": 23,
  "first_seen": "2026-04-09T11:30:00Z",
  "last_seen": "2026-04-09T11:53:00Z",
  "investigation_priority": "critical"
}
```

Priority assignment:
- **Critical**: 3+ kill chain phases, includes exfil or lateral movement
- **High**: 2+ phases, or any chain with privilege escalation
- **Medium**: 2 phases, discovery + execution type patterns
- **Low**: single phase, but multi-entity linkage

### 3. Alert Context Packages

Every pushed alert includes investigation context:

```python
def enrich_with_context(anomaly: dict, es: Elasticsearch) -> dict:
    """Add investigation context to an anomaly before push."""
    anomaly["context"] = {
        # Historical: how noisy is this entity?
        "entity_anomaly_count_7d": count_recent_anomalies(entity, days=7),
        "entity_anomaly_trend": "increasing",  # or "stable", "decreasing"
        
        # Peer comparison: is this score unusual?
        "score_percentile": compute_percentile(score, job_id),
        "score_percentile_label": "top 2%",
        
        # Evidence trail
        "source_es_doc_ids": [doc_id_1, doc_id_2],
        "source_index": "logs-endpoint.events.process-*",
        
        # Investigation hints
        "recommended_next_steps": [
            "Check process tree for webserver-01 around 11:30 UTC",
            "Review outbound connections to 10.0.1.5",
            "Verify if admin login at this hour is expected",
        ],
    }
    return anomaly
```

Investigation hints are templated per ATT&CK technique:
```python
INVESTIGATION_TEMPLATES = {
    "T1059": [
        "Review full command line arguments for the flagged process",
        "Check parent process — is this expected to spawn {process_name}?",
        "Look for similar commands on peer hosts in the same timeframe",
    ],
    "T1078": [
        "Verify the login source IP with the user/team",
        "Check if MFA was used for this authentication",
        "Review user's login history for the past 30 days",
    ],
}
```

### 4. Realtime Service Hardening (realtime_service.py)

Add operational resilience:

**Health metrics** (exposed via a simple JSON file or optional HTTP endpoint):
```json
{
  "last_detection_run": "2026-04-09T12:00:00Z",
  "last_detection_duration_sec": 45,
  "last_push_success_count": 12,
  "last_push_failure_count": 0,
  "last_correlation_chains": 2,
  "es_connection_healthy": true,
  "model_versions": {"process": "20260409_120000", "network": "20260409_120000"},
  "uptime_hours": 168
}
```

**Circuit breaker for ES push failures:**
```python
class CircuitBreaker:
    def __init__(self, failure_threshold: int = 5, reset_timeout_sec: int = 300):
        ...
    # After N consecutive push failures, stop pushing for reset_timeout
    # Buffer locally to results/push_buffer.jsonl
    # Resume after timeout, try one push — if success, close circuit
```

**Structured JSON logging:**
```python
import json, logging

class JSONFormatter(logging.Formatter):
    def format(self, record):
        return json.dumps({
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "module": record.module,
            "correlation_id": getattr(record, 'correlation_id', None),
            "message": record.getMessage(),
        })
```

Add `correlation_id` that traces a detection through detect → push → correlate.

### 5. ES Index Mappings (mappings/)

Create proper mappings for:
- `mappings/ml-anomalies-custom.json` — anomaly docs with MITRE fields
- `mappings/ml-anomalies-correlated.json` — correlation chain docs
- `mappings/template-install.py` — script to install index templates in ES

## Self-Validation
```bash
python validation/check_agent_6.py
```
Checks:
- ATT&CK mapping covers all job IDs in JOB_CONFIGURATIONS
- Kill chain phases are correctly ordered
- Correlation produces valid chains from synthetic correlated anomalies
- Context enrichment adds all required fields
- Circuit breaker triggers after N failures and resets
- JSON logging produces valid JSON
- No modifications to Agent 4's filter functions
- Index mappings are valid JSON
