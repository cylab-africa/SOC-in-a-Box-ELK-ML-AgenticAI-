# Agent 4: False Positive / False Negative Tuner

## Identity
You are the signal quality specialist. Your job is to ensure the pipeline
catches real attacks (low FN) while keeping SOC alert fatigue manageable (low FP).
You make filtering smarter, not harder.

## Files You Own (WRITE access)
- `benign_lists.py` — graduated allowlisting
- `config.py` — threshold-related sections only
- `push_all_anomalies.py` — ONLY the filtering/dedup sections (not enrichment)
- `missed_attack_audit.py` (new file you create)
- `requirements-tuning.txt` (create if needed)

## Files You Read (DO NOT MODIFY)
- `model_manager.py`, `detection_methods.py` — understand scoring
- `datamanager.py` — understand data flow
- `post_correlation.py` — understand what happens after push
- `anomaly_detector.py` — understand detection flow

## CRITICAL: Shared File Boundary
`push_all_anomalies.py` is shared with Agent 6. Your territory:
- FP filter functions (allowlist checks, score gating, dedup logic)
- Functions containing: `filter_`, `dedup_`, `is_benign`, `should_push`

Agent 6's territory:
- Enrichment functions: `enrich_`, `add_context_`, `map_mitre_`
- Bulk index / push functions
- Health metrics

DO NOT touch Agent 6's sections. If you need enrichment data for filtering
decisions, call their functions — don't rewrite them.

## What You Must Build

### 1. Graduated Allowlisting (benign_lists.py)

Replace binary allow/block with score modifiers:

```python
@dataclass
class AllowlistEntry:
    pattern: str              # regex or exact match
    match_type: str           # "exact", "prefix", "regex"
    dampening_factor: float   # multiply score by this (0.3 = heavy dampen)
    category: str             # "infrastructure", "monitoring", "system"
    expires_at: datetime | None  # None = permanent
    created_at: datetime
    hit_count: int = 0
    last_hit: datetime | None = None

NEVER_ALLOWLIST = [
    # LOLBins — these are too commonly abused to ever dampen
    "sudo", "ssh", "scp", "curl", "wget", "python", "python3",
    "perl", "ruby", "bash", "sh", "zsh", "nc", "ncat", "netcat",
    "socat", "awk", "sed", "dd", "tar", "gzip", "base64",
    "openssl", "nmap", "tcpdump", "strace", "ltrace", "gdb",
    "chmod", "chown", "crontab", "at", "systemctl",
]
```

Rules:
- If a process name is in NEVER_ALLOWLIST, skip all dampening
- Expired entries are logged and skipped (not applied)
- Every allowlist hit is logged to `results/allowlist_hits.jsonl`
- Entries older than 90 days without hits are flagged for review

### 2. Adaptive Thresholds (config.py)

Replace static `MIN_PUSH_ML_SCORE` with:

```python
@dataclass
class AdaptiveThreshold:
    base_score: float = 0.65
    per_job_overrides: dict[str, float] = field(default_factory=lambda: {
        "v3_linux_anomalous_network_activity": 0.55,  # network needs lower bar
        "v3_linux_rare_sudo_activity": 0.70,           # sudo is noisy
    })
    off_hours_multiplier: float = 0.85  # lower threshold 6PM-6AM
    high_value_host_multiplier: float = 0.80  # lower for critical hosts
    high_value_hosts: list[str] = field(default_factory=list)  # from config
```

Store threshold decisions in `results/threshold_audit.json`:
```json
{
  "timestamp": "2026-04-09T12:00:00Z",
  "job_id": "v3_linux_anomalous_process_all_hosts",
  "entity": "webserver-01",
  "raw_score": 0.72,
  "effective_threshold": 0.52,
  "reason": "base=0.65, off_hours=*0.85, high_value_host=*0.80 -> 0.52",
  "decision": "push"
}
```

### 3. Intelligent Dedup (push_all_anomalies.py filtering section)

Replace flat `MAX_ALERTS_PER_TYPE_PER_DAY` with:

- **4-hour windows** instead of daily (attacks happen fast)
- **Score escalation override**: if same entity+job hits dedup but score
  is ≥ 20% higher than last pushed score, force-push as "escalation"
- **Cluster similar alerts**: group by entity+job within window,
  push one representative + `"similar_count": N`
- **Never dedup correlated chains**: if post_correlation flags a chain,
  all members bypass dedup

### 4. Filter Traceability

Every filtering decision gets a `filter_trace` field:
```python
{
    "filter_trace": {
        "allowlist_checked": true,
        "allowlist_match": "systemd-*",
        "dampening_applied": 0.3,
        "original_score": 0.82,
        "dampened_score": 0.246,
        "threshold_used": 0.65,
        "threshold_components": {"base": 0.65, "time_adj": 1.0, "host_adj": 1.0},
        "dedup_status": "first_occurrence",
        "final_decision": "dropped_below_threshold",
    }
}
```

### 5. Missed Attack Audit Tool (missed_attack_audit.py)

Standalone script:
```bash
python missed_attack_audit.py --iocs indicators.json --timerange 24h
```

Input: JSON with known-bad indicators (IPs, process names, hashes, timestamps)
Output: For each indicator, trace through the pipeline:
- Was it fetched from ES? (check datamanager queries)
- Was it scored? (check detection results)
- What was the score? (check raw anomaly output)
- Was it allowlisted? (check benign_lists)
- Was it below threshold? (check adaptive threshold)
- Was it deduped? (check dedup state)
- Was it pushed? (check push results)

Report format: JSON + human-readable markdown summary.

## Self-Validation
```bash
python validation/check_agent_4.py
```
Checks:
- LOLBins in NEVER_ALLOWLIST are never dampened (test each one)
- Expired allowlist entries are not applied
- Adaptive threshold produces correct values for test scenarios
- Score escalation correctly bypasses dedup
- filter_trace field is present on all processed records
- missed_attack_audit.py runs on synthetic data without error
- No modifications to files outside ownership (especially not enrichment sections)
