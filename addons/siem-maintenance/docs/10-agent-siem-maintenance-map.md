# 10. This repository — `Agent-SIEM-maintenance` (maintenance-only)

Start with [**docs/00 — Design spec vs this repo**](00-design-spec-vs-this-repo.md) for a section-by-section map to the narrative specification.  
Sections [1](01-what-is-watched.md)–[9](09-deployment.md) describe the **packaged** `siem_maint` installer. **This repo** is a slim slice: **five Python modules** for Elasticsearch health, daily Chat reporting, and optional auto-remediation.

## 10.1 Python modules

| File | Role |
|------|------|
| **`maintenance_service.py`** | Run in the foreground: **APScheduler** — morning report (`ultra_siem_monitor --alert`) at **`DAILY_REPORT_TIME_CAT`** in **`MAINTENANCE_IANA_TIMEZONE`**, plus **`es_health_monitor.py`** every **`SIEM_HEALTH_POLL_INTERVAL_SECONDS`** (or **`ES_HEALTH_MONITOR_INTERVAL_SECONDS`**). |
| **`ultra_siem_monitor.py`** | Daily report CLI: calls **`enhanced_health_monitor.py`**; writes `results/health_analysis_*.json` and optional `daily_health_report_latest.html`. |
| **`enhanced_health_monitor.py`** | Cluster + ingestion snapshot, **LLM** recommendations (OpenAI if `LLM_MODEL` starts with `gpt-`, else **Ollama**), **Google Chat** card via **`GC_ALERT_WEBHOOK`**. Imports **`es_health_monitor`** as a library. |
| **`es_health_monitor.py`** | Deep health checks, freshness, shards, **LLM** blocks when alerting; Chat with **`ES_ALERT_COOLDOWN_HOURS`**. |
| **`auto_remediate.py`** | **Manual / cron**: `--investigate-only`, `--dry-run`, `--auto-fix` — safe ES remediations + Chat summary. Not started by `maintenance_service.py`. |

## 10.2 Escalation (Google Chat)

| Stage | Channel | Variables |
|-------|---------|-----------|
| Infrastructure health / daily report | Google Chat (maintenance) | `GC_ALERT_WEBHOOK`, `GC_ALERT_SPACE_NAME` |

LLM output is **recommendation only** ([§8.3](08-agentic-behaviors.md)).

## 10.3 Environment

`ultra_siem_monitor.py` and `maintenance_service.py` load **`../.env`** then **`Agent-SIEM-maintenance/.env`** (local overrides).  
`es_health_monitor.py` and `auto_remediate.py` read the process environment only — run them from the same shell after loading `.env`, or use **dotenv** / **export** in your process manager.

**Commonly used:** `ES_HOST`, `ES_USERNAME`, `ES_PASSWORD`, `ES_PROCESS_INDEX`, `ES_NETWORK_INDEX`, `ES_DISCOVERY_INDEX`, `ES_QUERY_*`, `ES_ALERT_COOLDOWN_HOURS`, `ES_HEALTH_LLM_MODEL`, `LLM_MODEL`, `LLM_ENABLED`, `OPENAI_API_KEY`, `OLLAMA_URL`, `GC_ALERT_WEBHOOK`, `GC_ALERT_SPACE_NAME`, `LOG_LEVEL`, `DAILY_REPORT_TIME_CAT`, `MAINTENANCE_IANA_TIMEZONE`, `SIEM_HEALTH_POLL_INTERVAL_SECONDS` / `ES_HEALTH_MONITOR_INTERVAL_SECONDS`, `ML_FILE_RETENTION_DAYS` (auto-remediation cleanup).

---

Previous: [← 9. Deployment guide](09-deployment.md) · [0. Spec vs repo](00-design-spec-vs-this-repo.md)  
Next: [11. QA — Python file scope →](11-qa-python-scope.md)
