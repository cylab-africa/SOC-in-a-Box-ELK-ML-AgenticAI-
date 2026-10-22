# 3. Thresholds and Alert Bands

> **This repository:** issue severity and transitions are implemented inside **`es_health_monitor.py`** (not `alerting/classify.py`). See [**docs/00**](00-design-spec-vs-this-repo.md).

Every watched metric has three bands: **healthy**, **warning**, and
**critical**. The platform pages on band transitions, not on sample
values — a metric that stays in the same band for a hundred
consecutive samples produces zero alerts, and a metric that crosses
a threshold produces exactly one. This is the single most important
design choice for keeping the chat channel usable in production.

## 3.1 How the bands are chosen

**Warning** thresholds are set where the operator still has time to
act without an emergency response — typically around 75–80% of
capacity for bounded resources like heap, memory, and disk.

**Critical** thresholds are set where the system will start failing
in the near term if nothing changes:

- **85% heap** — JVM garbage collection starts thrashing beyond that.
- **90% disk** — that is the Elasticsearch flood-stage watermark.

For discrete metrics (cluster status, unassigned shards, thread-pool
rejections) the bands map directly onto the state space — *any*
primary shard unassigned is critical regardless of count, because
the data is unavailable until allocation recovers.

## 3.2 Transition alerting, not sample alerting

The subsystem keeps a last-known state per metric on disk. When a
new sample lands, it classifies the value into a band and compares
against the stored state.

- If the band has changed — healthy → warning, warning → critical,
  or any transition back toward healthy — an alert is generated.
- If the band has not changed, the sample is logged at debug level
  and discarded.

A five-minute window of continuously-critical CPU load produces
**one** alert, not sixty. A metric that oscillates between warning
and critical still produces one alert per transition, which is
exactly the signal an operator needs.

**`siem_maint/alerting/classify.py`**

```python
import json
from pathlib import Path

STATE_FILE = Path("/var/lib/siem-maint/last_bands.json")

def classify(metric, value):
    """Return 'healthy', 'warning', or 'critical' for a (metric, value) pair."""
    if metric == "heap_pct":
        if value < 75: return "healthy"
        if value < 85: return "warning"
        return "critical"
    if metric == "disk_pct":
        if value < 80: return "healthy"
        if value < 90: return "warning"
        return "critical"
    # ... more rules per metric

def detect_transition(metric, value):
    state = json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}
    new_band = classify(metric, value)
    old_band = state.get(metric)
    if new_band != old_band:
        state[metric] = new_band
        STATE_FILE.write_text(json.dumps(state))
        return (old_band, new_band)   # transition — caller will alert
    return None                       # no change — caller drops sample
```

---

Previous: [← 2. When each check runs](02-cadence.md)
Next: [4. The remediation loop →](04-remediation-loop.md)
