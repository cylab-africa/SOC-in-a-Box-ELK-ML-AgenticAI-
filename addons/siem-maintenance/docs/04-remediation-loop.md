# 4. The Remediation Loop

> **This repository:** see **`auto_remediate.py`** and [**docs/00**](00-design-spec-vs-this-repo.md) for mapping to `remediation/apply.py` / `fixes.py`.

For a narrow class of Elasticsearch problems, the subsystem does not
just alert — it fixes. The policy is deliberately conservative:

- Only issues that are both well-understood and trivially reversible
  get automated.
- Every automated action is verified after the fact.
- Complex problems never get auto-fixed — they get a structured
  recommendation routed to SIEM-MAINTENANCE with the three commands
  an operator should run to diagnose, fix, and verify.

## 4.1 Investigate, fix, verify

Every remediation follows the same three-stage loop.

1. **Investigate** — gather current cluster state through the same
   APIs used for health monitoring (cluster health, node stats,
   shard allocation, thread-pool metrics, ILM status) and categorise
   any issues found.
2. **Fix** — pre-validate each proposed fix against three checks:
   - Is this issue type on the safe-auto-fix list?
   - Has this exact fix been applied within the last 24 h? (prevents
     remediation loops)
   - Is the target resource on the protected list?

   Only if all three pass does the fix execute.
3. **Verify** — re-check the same metric that triggered the fix,
   confirm improvement, write the full audit trail to a JSONL file,
   and post a chat notification describing what was found, what was
   done, and whether it worked.

**`siem_maint/remediation/apply.py`**

```python
PROTECTED = (".ds-logs-endpoint.events.", ".internal.alerts-",
             "logs-endpoint.events.", ".fleet-", ".security-")

SAFE_FIX_TYPES = {"scroll_leak", "rejections", "fielddata", "segments",
                  "old_ml_results", "stuck_ilm", "unassigned_shards"}

def is_protected(target):
    return any(target.startswith(p) for p in PROTECTED)

def already_applied_recently(fix_id):
    # check audit JSONL for the same fix in the last 24h
    return audit.has_within(fix_id, hours=24)

def apply_fix(issue):
    if issue.type not in SAFE_FIX_TYPES:       return "escalate_to_llm"
    if is_protected(issue.target):             return "blocked_protected"
    if already_applied_recently(issue.fix_id): return "blocked_loop"

    result = FIX_HANDLERS[issue.type](es, issue)
    audit.write(issue, result)
    return result
```

## 4.2 The seven safe auto-fixes

Each of the seven entries below survived the question *"what is the
worst thing that happens if this runs at the wrong time?"* without a
concerning answer.

| Issue | Detection signal | Automatic fix | Verification |
|-------|------------------|---------------|--------------|
| Scroll context leak | open scrolls > 80% of limit | `DELETE _search/scroll/_all` | recheck open scroll count |
| Thread-pool saturation | rejections > 0 | adjust `queue_size` dynamically | confirm rejections stop |
| Fielddata pressure | cache > 30% of heap | `POST _cache/clear?fielddata=true` | confirm heap drops |
| Shard fragmentation | > 50 segments per shard | `forcemerge max_num_segments=1` | verify segment count |
| Stale ML result files | indices > 7 days old | delete old daily indices | verify disk recovered |
| Stuck ILM phase | phase execution stuck | `POST _ilm/retry` | verify ILM progresses |
| Unassigned shards | allocation failures | `cluster reroute retry_failed` | verify shards assigned |

The four most common fixes all reduce to one or two API calls.

**Clear all open scroll contexts (curl)**

```bash
curl -s -u "$ES_USER:$ES_PASS" \
  -X DELETE "https://es-host:9200/_search/scroll/_all"
```

**Clear fielddata cache cluster-wide (curl)**

```bash
curl -s -u "$ES_USER:$ES_PASS" \
  -X POST "https://es-host:9200/_cache/clear?fielddata=true"
```

**Force-merge an index to a single segment (curl)**

```bash
curl -s -u "$ES_USER:$ES_PASS" \
  -X POST "https://es-host:9200/<index>/_forcemerge?max_num_segments=1"
```

**Retry failed shard allocations (curl)**

```bash
curl -s -u "$ES_USER:$ES_PASS" \
  -X POST "https://es-host:9200/_cluster/reroute?retry_failed=true"
```

**`siem_maint/remediation/fixes.py`**

```python
def fix_scroll_leak(es, issue):
    return es.clear_scroll(scroll_id="_all")

def fix_rejections(es, issue):
    return es.cluster.put_settings(persistent={
        "thread_pool." + issue.pool + ".queue_size": issue.new_queue_size
    })

def fix_fielddata(es, issue):
    return es.indices.clear_cache(fielddata=True)

def fix_segments(es, issue):
    return es.indices.forcemerge(index=issue.target, max_num_segments=1)

def fix_old_ml_results(es, issue):
    return es.indices.delete(index=issue.target)  # only matched daily indices

def fix_stuck_ilm(es, issue):
    return es.ilm.retry(index=issue.target)

def fix_unassigned_shards(es, issue):
    return es.cluster.reroute(retry_failed=True)

FIX_HANDLERS = {
    "scroll_leak":       fix_scroll_leak,
    "rejections":        fix_rejections,
    "fielddata":         fix_fielddata,
    "segments":          fix_segments,
    "old_ml_results":    fix_old_ml_results,
    "stuck_ilm":         fix_stuck_ilm,
    "unassigned_shards": fix_unassigned_shards,
}
```

## 4.3 Protected resources — never touched

Five index patterns are hardcoded as essential and are excluded from
every remediation code path:

- `.ds-logs-endpoint.events.*` — all endpoint telemetry data
- `.internal.alerts-*` — SIEM detection rule alerts
- `logs-endpoint.events.*` — alternative endpoint index pattern
- `.fleet-*` — agent management data
- `.security-*` — Elasticsearch security configuration

No fix, no deletion, no forcemerge, no reroute — ever. These patterns
are checked before every action, and a pattern match aborts the
action with a log entry explaining why.

## 4.4 When the LLM gets involved

Problems that fall outside the seven auto-fixes are handed to the
configured LLM for a **recommendation, not a fix**. The prompt passes
only factual observations — short declarative sentences like
*"cluster status is yellow"* and *"node es-data-02 JVM heap at
87 percent"* — and asks for exactly three commands:

1. One to **diagnose** the problem.
2. One to **fix** it.
3. One to **verify** the fix.

The three commands are posted to chat so the operator can copy-paste
them directly. If the LLM is unavailable (timeout, model not loaded,
network error), the subsystem falls back to a pre-built library of
recommendations covering eight categories and returns the canned
guidance instead. Everything continues running.

The LLM backend is a local [Ollama](https://ollama.com) server — see
the [Installation section in the README](../README.md#install-with-soc-in-a-box)
for setup. Using a local model means no observations about the
cluster ever leave the host.

**LLM recommendation client** (called from `siem_maint/remediation/apply.py` when `apply_fix` returns `escalate_to_llm`)

```python
import os
import ollama

OLLAMA_HOST  = os.environ.get("OLLAMA_HOST",  "http://127.0.0.1:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "gemma4:e4b")

client = ollama.Client(host=OLLAMA_HOST)

SYSTEM_PROMPT = (
    "You are an Elasticsearch SRE assistant. Given factual observations "
    "about a cluster, return exactly three shell commands: one to "
    "diagnose, one to fix, one to verify. No prose."
)

def recommend(observations: list[str]) -> list[str] | None:
    try:
        resp = client.chat(
            model=OLLAMA_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": "\n".join(observations)},
            ],
            options={"temperature": 0.1},
        )
        return parse_three_commands(resp["message"]["content"])
    except Exception:
        return None  # caller falls back to the canned library
```

---

Previous: [← 3. Thresholds and alert bands](03-thresholds-and-alert-bands.md)
Next: [5. From breach to Google Chat →](05-alert-routing.md)
